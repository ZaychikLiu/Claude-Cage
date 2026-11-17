export async function copyGuestText({ request, sendCopy, valid }) {
  const before = await request({ phase: "prepare" });
  if (!valid() || typeof before.revision !== "number" || typeof before.session !== "string") throw new Error("复制窗口已变化，请重新选择文本。");
  await sendCopy();
  if (!valid()) throw new Error("复制窗口已变化，请重新选择文本。");
  const result = await request({ phase: "read", revision: before.revision, session: before.session });
  if (!valid() || result.session !== before.session || result.revision === before.revision || typeof result.text !== "string") {
    throw new Error("未收到新的选中文本，请重新选择后复制。");
  }
  return { text: result.text };
}

// A guest whose clipboard service keeps failing, for example while its
// components wait for an update, must not be hit every 1.5 seconds.
export const clipboardReconnectDelay = failures => Math.min(1500 * 2 ** Math.max(0, failures), 30000);

// One connection owns clipboard synchronization for the workbench window,
// including while its remote canvas is hidden or the window is unfocused.
export function shareClipboard({ connect, native, onStatus, setActive, interval = 300, schedule = setTimeout }) {
  let socket, timer, retry, disposed = false, revision, generation = 0, guestReady = false, guestSession, failures = 0;
  let polling, repoll = false, repollInitial = false, writes = Promise.resolve(), lastPayload = "", serial = 0, errorShown = false, acknowledgedRevision, guestRevision, supersededUntil = 0, pendingGuestWrites = 0;
  let sessionGeneration = 0;
  let sessionController = new AbortController();
  const acknowledgements = new Map();
  const fileReferences = new Map();
  const retainFiles = value => {
    const id = value?.files;
    if (typeof id !== "string") return () => {};
    fileReferences.set(id, (fileReferences.get(id) || 0) + 1);
    return () => {
      const remaining = fileReferences.get(id) - 1;
      if (remaining) { fileReferences.set(id, remaining); return; }
      fileReferences.delete(id);
      void native("clipboardSyncRelease", { files: id }).catch(() => {});
    };
  };
  const disconnected = () => new Error("剪贴板连接已变化，请确认客机已连接后重新粘贴。");
  const invalidateSession = () => {
    generation++; sessionGeneration++;
    sessionController.abort(); sessionController = new AbortController();
    guestReady = false;
    polling = undefined; repoll = false; repollInitial = false; writes = Promise.resolve(); supersededUntil = 0;
    for (const pending of acknowledgements.values()) pending.reject();
    acknowledgements.clear();
    setActive(false);
    void native("clipboardSyncCancel").catch(() => {});
  };
  const requireSession = signal => {
    if (disposed || signal.aborted || !guestReady || socket?.readyState !== 1) throw disconnected();
  };
  const waitForSession = (work, signal) => new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener("abort", abort); reject(disconnected()); };
    Promise.resolve(work).then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  });
  const warn = () => { if (!disposed && !errorShown) { errorShown = true; onStatus("剪贴板共享暂未完成，请检查文件是否仍存在及大小限制。"); } };
  const send = (connection, content, basedOnRevision) => new Promise((resolve, reject) => {
    const id = ++serial;
    const timeoutMs = content.png ? 30000 : 10000;
    const timeout = setTimeout(() => { acknowledgements.delete(id); reject(new Error("Clipboard acknowledgement timed out")); }, timeoutMs);
    acknowledgements.set(id, { resolve: value => { clearTimeout(timeout); resolve(value); }, reject: () => { clearTimeout(timeout); reject(new Error("Clipboard disconnected")); } });
    // Tell the guest which revision this snapshot was built from so it can
    // refuse to overwrite a copy the user made while the transfer was in flight.
    const basedOn = typeof basedOnRevision === "number" ? basedOnRevision
      : typeof guestRevision === "number" ? guestRevision : undefined;
    try { connection.send(JSON.stringify({ ...content, serial: id, ...(basedOn === undefined ? {} : { basedOn }) })); }
    catch { acknowledgements.get(id)?.reject(); acknowledgements.delete(id); }
  });
  const payload = value => typeof value.text === "string" ? { text: value.text }
    : typeof value.png === "string" ? { png: value.png }
      : typeof value.files === "string" ? { files: value.files } : null;
  const readHost = async (initial = false) => {
    if (disposed || !guestReady || socket?.readyState !== 1) return;
    const currentSocket = socket, currentGeneration = generation, session = sessionGeneration;
    let releaseFiles = () => {};
    try {
      // Capture the guest revision before deciding to snapshot: anything the
      // user copies afterwards, in either place, must outrank this snapshot.
      const basedOn = guestRevision;
      const current = await native("clipboardRevision");
      if (typeof current !== "number") throw new Error("Clipboard revision unavailable");
      // The guest refused the last snapshot because it copied something newer;
      // give its publish a moment to arrive before offering ours again.
      if (!initial && Date.now() < supersededUntil) return;
      if (!initial && current === revision && current === acknowledgedRevision) return;
      const value = await native("clipboardSyncRead");
      releaseFiles = retainFiles(value);
      const content = payload(value);
      const finalRevision = await native("clipboardRevision");
      if (disposed || !guestReady || socket !== currentSocket || currentGeneration !== generation ||
          value.revision !== finalRevision) return;
      revision = value.revision;
      if (!content) throw new Error("Clipboard content unavailable");
      if (pendingGuestWrites > 0) {
        // Wait for the guest's copy to land before offering a snapshot read
        // earlier; if it changed this machine's clipboard, the snapshot is stale.
        await Promise.resolve(writes).catch(() => {});
        if (await native("clipboardRevision") !== value.revision) return;
      }
      const encoded = JSON.stringify(content);
      if (initial || value.revision !== acknowledgedRevision || encoded !== lastPayload) {
        const reply = await send(currentSocket, content, basedOn);
        if (reply?.error === "superseded") {
          supersededUntil = Date.now() + 1500;
          acknowledgedRevision = undefined;
          lastPayload = "";
          void poll().catch(warn);
          return;
        }
        if (typeof reply?.revision === "number") guestRevision = reply.revision;
      }
      if (disposed || !guestReady || socket !== currentSocket || currentGeneration !== generation) return;
      acknowledgedRevision = value.revision;
      lastPayload = encoded;
      setActive(true);
      errorShown = false;
      failures = 0;
    } catch {
      if (disposed || socket !== currentSocket || session !== sessionGeneration) return;
      warn();
      setActive(false);
      revision = undefined; lastPayload = "";
      currentSocket.close();
      throw new Error("Clipboard synchronization failed");
    } finally { releaseFiles(); }
  };
  let repollGeneration = 0;
  const poll = (initial = false) => {
    if (!polling) {
      repollGeneration = generation;
      const current = readHost(initial).finally(() => {
        if (polling === current) {
          polling = undefined;
          const shouldRepoll = repoll && repollGeneration === generation && !disposed && guestReady && socket?.readyState === 1;
          const nextInitial = repollInitial;
          repoll = false;
          repollInitial = false;
          if (shouldRepoll) void poll(nextInitial).catch(warn);
        }
      });
      polling = current;
    } else if (repollGeneration === generation) {
      repoll = true;
      repollInitial = repollInitial || initial;
    }
    return polling;
  };
  const receive = (value) => {
    if (typeof value.revision === "number") guestRevision = value.revision;
    if (value.hello) {
      const hello = value.hello;
      const supported = hello.version === 1 && ["linux", "windows", "darwin"].includes(hello.os) &&
        typeof hello.session === "string" && hello.session.length > 0 &&
        ["text", "png", "files"].every(format => hello.formats?.includes(format));
      const previouslyReady = guestReady;
      if (previouslyReady && (guestSession !== hello.session || !supported || !hello.available)) invalidateSession();
      if (guestSession !== hello.session) {
        // A new GUI session starts the version history over. A plain transport
        // reconnect under the same session must keep it, otherwise the seed
        // below overwrites whatever the guest copied while disconnected.
        revision = undefined; acknowledgedRevision = undefined; lastPayload = ""; guestRevision = undefined;
      }
      guestSession = hello.session;
      guestReady = supported && hello.available === true;
      if (typeof hello.revision === "number") guestRevision = hello.revision;
      if (!guestReady) setActive(false);
      if (guestReady && revision === undefined) void poll(true).catch(warn);
      return;
    }
    if (value.ack) {
      if (typeof value.revision === "number") guestRevision = value.revision;
      acknowledgements.get(value.ack)?.resolve(value); acknowledgements.delete(value.ack); return;
    }
    if (value.error) {
      const pending = value.serial ? acknowledgements.get(value.serial) : undefined;
      if (pending) {
        acknowledgements.delete(value.serial);
        if (typeof value.revision === "number") guestRevision = value.revision;
        pending.resolve(value);
        return;
      }
      if (value.error === "superseded") {
        supersededUntil = Date.now() + 1500;
        void poll().catch(warn);
        return;
      }
      warn(); socket?.close(); return;
    }
    const content = payload(value), sequence = ++generation, currentSocket = socket, session = sessionGeneration;
    if (!content) return;
    const releaseFiles = retainFiles(content);
    // While the guest's copy is being written to this machine, a snapshot the
    // host read before it arrived must not race it back to the guest.
    pendingGuestWrites++;
    writes = writes.then(async () => {
      if (disposed || !guestReady || socket !== currentSocket || sequence !== generation) return;
      const current = await native("clipboardRevision");
      if (disposed || !guestReady || socket !== currentSocket || sequence !== generation) return;
      if (revision === undefined || current !== revision) {
        // A newer local copy wins over an update that was already in transit.
        void poll().catch(warn);
        return;
      }
      if (JSON.stringify(content) === lastPayload) return;
      const result = await native("clipboardSyncWrite", { ...content, revision });
      if (disposed || socket !== currentSocket || session !== sessionGeneration) return;
      if (result.superseded) { void poll().catch(warn); return; }
      revision = result.revision;
      acknowledgedRevision = result.revision;
      lastPayload = JSON.stringify(content);
      onStatus(content.files ? "文件已复制到本机，可在本机粘贴" : "已复制到本机");
    }).catch(() => {
      if (session === sessionGeneration) warn();
    }).finally(() => {
      pendingGuestWrites--;
      releaseFiles();
    });
  };
  const open = () => {
    if (disposed) return;
    guestReady = false;
    socket = connect();
    const connection = socket;
    socket.onopen = () => {
      if (disposed || socket !== connection) return;
      timer = setInterval(() => void poll().catch(warn), interval);
    };
    socket.onmessage = event => {
      if (disposed || socket !== connection) return;
      try { receive(JSON.parse(event.data)); } catch { /* Invalid transport data is not a clipboard change. */ }
    };
    socket.onclose = () => {
      if (disposed || socket !== connection) return;
      invalidateSession(); clearInterval(timer);
      retry = schedule(open, clipboardReconnectDelay(failures++));
    };
    socket.onerror = () => { /* onclose owns reconnects. */ };
  };
  open();
  return { poll, ready: () => !disposed && guestReady && socket?.readyState === 1, async sync() {
    const signal = sessionController.signal;
    requireSession(signal);
    // A second clipboard bridge (the native Screen Sharing window) or a slow
    // file snapshot can keep producing updates; a paste must not wait forever.
    const deadline = Date.now() + 5000;
    const within = work => Promise.race([
      work,
      new Promise((_, reject) => setTimeout(() => reject(new Error("剪贴板同步超时，请稍后重试。")), Math.max(0, deadline - Date.now()))),
    ]);
    for (;;) {
      if (Date.now() > deadline) throw new Error("剪贴板同步超时，请稍后重试。");
      await waitForSession(within(poll()), signal);
      const pendingWrites = writes;
      await waitForSession(within(pendingWrites), signal);
      const sequence = generation;
      const current = await waitForSession(within(native("clipboardRevision")), signal);
      requireSession(signal);
      if (typeof current !== "number") throw new Error("无法确认当前剪贴板版本，请重新粘贴。");
      if (current === acknowledgedRevision && sequence === generation && pendingWrites === writes) return;
    }
  }, dispose() {
    disposed = true; invalidateSession(); clearInterval(timer); clearTimeout(retry);
    socket?.close();
  } };
}
