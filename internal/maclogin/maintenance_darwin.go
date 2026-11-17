//go:build darwin && (amd64 || (arm64 && cgo && !no_vz))

package maclogin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"time"

	"al.essio.dev/pkg/shellescape"
	"github.com/sylvinus/agent-vm/internal/guestos"
)

func (s *loginSession) maintenanceIdentity(open bool) (string, string, error) {
	if !guestos.ValidMacMaintenancePurpose(s.maintenance) {
		return "", "", errors.New("维护用途无效")
	}
	bound, err := guestos.LoadMacOSProfile(s.profile)
	if err != nil || bound == nil || bound.SetupID != "" {
		return "", "", errors.New("请先完成虚拟 Mac 的首次设置")
	}
	if open {
		s.maintenanceMachineID = bound.MachineID
	} else if s.maintenanceMachineID != bound.MachineID {
		return "", "", errors.New("虚拟 Mac 身份已变化，请重新打开维护画面")
	}
	user, err := guestos.MacOSProvisionUser(s.profile)
	if err != nil {
		return "", "", err
	}
	if open {
		s.maintenanceAdministrator = user
	} else if s.maintenanceAdministrator != user {
		return "", "", errors.New("客机安装身份已变化，请重新打开维护画面")
	}
	return user, bound.User, nil
}

func (s *loginSession) maintenanceCommand(ctx context.Context, operation string) (*exec.Cmd, string, error) {
	user, guestUser, err := s.maintenanceIdentity(operation == "--maintenance-open")
	if err != nil {
		return nil, "", err
	}
	cmd, err := guestGUIProbeCommand(ctx, s.profile, user, guestUser, operation, s.maintenance)
	return cmd, guestUser, err
}

func queryCompositorMaintenance(probe *passwordProbe, user string) (maintenanceWindow, bool, error) {
	var result maintenanceWindow
	if _, err := io.WriteString(probe.input, "{\"action\":\"probe\"}\n"); err != nil {
		return result, false, err
	}
	if !probe.scanner.Scan() {
		return result, false, errors.New("compositor probe stream closed")
	}
	if err := json.Unmarshal(probe.scanner.Bytes(), &result); err != nil {
		return result, false, err
	}
	if result.Error != "" {
		return result, true, errors.New(result.probeMessage())
	}
	if !result.valid(user) {
		return result, true, errors.New("客机授权窗口身份无法确认，请重新打开维护画面")
	}
	return result, true, nil
}

func (s *loginSession) maintenanceProbe(open bool) (maintenanceWindow, error) {
	var result maintenanceWindow
	operation := "--maintenance-probe"
	if open {
		operation = "--maintenance-open"
	} else if s.maintenanceCompositor != nil {
		if cached, ok, err := queryCompositorMaintenance(s.maintenanceCompositor, s.maintenanceCompositor.user); ok {
			return cached, err
		}
		s.maintenanceCompositor.close()
		s.maintenanceCompositor = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd, user, err := s.maintenanceCommand(ctx, operation)
	if err != nil {
		return result, err
	}
	pipe, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		result.Error = "component_update_required"
		return result, errors.New("客机维护组件尚未连接，请更新环境组件后重试")
	}
	data, readErr := io.ReadAll(io.LimitReader(pipe, 8193))
	if readErr != nil || len(data) > 8192 {
		cancel()
	}
	if err = cmd.Wait(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 73 {
			result.Error = "requires_gui_login"
			return result, errors.New("请先登录并解锁虚拟 Mac 的客机账户")
		}
		result.Error = "component_update_required"
		return result, errors.New("客机维护组件需要更新，请在环境设置中更新组件")
	}
	if readErr != nil || len(data) > 8192 || json.Unmarshal(data, &result) != nil {
		result.Error = "component_update_required"
		return result, errors.New("客机维护组件需要更新，请在环境设置中更新组件")
	}
	if result.Error != "" {
		if !open && result.Error == "maintenance_window_obscured" && (result.BlockingBundle == "com.apple.notificationcenterui" || result.BlockingBundle == "com.apple.dock" || result.BlockingBundle == "") {
			if stream, openErr := s.openCompositorProbe(5*time.Minute, false); openErr == nil {
				if fallback, ok, fallbackErr := queryCompositorMaintenance(stream, user); ok && fallbackErr == nil {
					s.maintenanceCompositor = stream
					return fallback, nil
				}
				stream.close()
			}
		}
		return result, errors.New(result.probeMessage())
	}
	if !open && !result.valid(user) {
		return result, errors.New("客机授权窗口身份无法确认，请重新打开维护画面")
	}
	return result, nil
}

const macOSCompositorProbeJXA = `
ObjC.import("AppKit");
ObjC.import("ApplicationServices");
ObjC.import("CoreGraphics");
ObjC.import("Foundation");

const sigCache = {};
function codesignOK(pid, bundlePath, bundleID) {
  if (!bundlePath || !bundleID) return false;
  const key = pid + ":" + bundleID + ":" + bundlePath;
  if (key in sigCache) return sigCache[key];
  const t = $.NSTask.alloc.init;
  t.executableURL = $.NSURL.fileURLWithPath("/usr/bin/codesign");
  t.arguments = $(["--verify", "--strict", "-R", ` + "`" + `=anchor apple and identifier "${bundleID}"` + "`" + `, bundlePath]);
  t.standardOutput = $.NSFileHandle.fileHandleWithNullDevice;
  t.standardError = $.NSFileHandle.fileHandleWithNullDevice;
  const ok = Boolean(t.launchAndReturnError(null)) && (t.waitUntilExit, t.terminationStatus === 0);
  sigCache[key] = ok;
  return ok;
}

function activeSession(expectedUser) {
  const sh = $.NSTask.alloc.init;
  sh.executableURL = $.NSURL.fileURLWithPath("/bin/sh");
  sh.arguments = $(["-c", "/usr/sbin/ioreg -a -n Root -r -d 1 | /usr/bin/plutil -convert json -o - -"]);
  const pipe = $.NSPipe.pipe;
  sh.standardOutput = pipe;
  sh.standardError = $.NSFileHandle.fileHandleWithNullDevice;
  if (!sh.launchAndReturnError(null)) return null;
  const data = pipe.fileHandleForReading.readDataToEndOfFile;
  sh.waitUntilExit;
  if (sh.terminationStatus !== 0) return null;
  const str = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding);
  const root = JSON.parse(ObjC.unwrap(str));
  const users = (Array.isArray(root) ? root[0]?.IOConsoleUsers : root?.IOConsoleUsers) || [];
  const active = users.filter(u => u.kCGSSessionOnConsoleKey === true);
  if (active.length !== 1) return null;
  const cur = active[0];
  if (cur.kCGSessionLoginDoneKey !== true || cur.CGSSessionScreenIsLocked === true) return null;
  if (cur.kCGSSessionUserNameKey !== expectedUser) return null;
  return cur.CGSSessionUniqueSessionUUID || null;
}

let systemEventsApp = null;
function passwordFocused(pid, rx, ry, rw, rh) {
  if (!$.AXIsProcessTrusted()) return false;
  try {
    if (!systemEventsApp) systemEventsApp = Application("System Events");
    const proc = systemEventsApp.processes.whose({ unixId: pid })[0];
    const f = proc.attributes.byName("AXFocusedUIElement").value();
    if (!f || f.subrole() !== "AXSecureTextField" || f.attributes.byName("AXEnabled").value() !== true) return false;
    const fp = f.position(), fs = f.size();
    if (!fp || !fs || fs[0] <= 0 || fs[1] <= 0) return false;
    if (fp[0] < rx || fp[1] < ry || fp[0] + fs[0] > rx + rw || fp[1] + fs[1] > ry + rh) return false;
    const matchesTarget = (el) => {
      try {
        const role = el.role();
        if (role !== "AXSheet" && role !== "AXWindow") return false;
        const p = el.position(), s = el.size();
        return Math.abs(p[0] - rx) < 1 && Math.abs(p[1] - ry) < 1 && Math.abs(s[0] - rw) < 1 && Math.abs(s[1] - rh) < 1;
      } catch (e) { return false; }
    };
    try {
      const win = f.attributes.byName("AXWindow").value();
      if (win && matchesTarget(win)) return true;
    } catch (e) {}
    let cur = f;
    for (let i = 0; i < 12; i++) {
      try { cur = cur.attributes.byName("AXParent").value(); } catch (e) { return false; }
      if (!cur) return false;
      if (matchesTarget(cur)) return true;
    }
  } catch (e) {}
  return false;
}

function runProbe(passwordMode) {
  const errPrefix = passwordMode ? "setup_password_" : "maintenance_";
  const user = ObjC.unwrap($.NSUserName());
  const session = activeSession(user);
  if (!session) return { error: "requires_gui_login" };
  const front = $.NSWorkspace.sharedWorkspace.frontmostApplication;
  if (front.isNil()) return { error: errPrefix + "foreground_changed" };
  const frontPID = front.processIdentifier;
  const frontBundle = ObjC.unwrap(front.bundleIdentifier) || "";
  const frontPath = front.bundleURL.isNil() ? "" : ObjC.unwrap(front.bundleURL.path);
  const allowedApps = passwordMode
    ? ["com.apple.systempreferences", "com.apple.authorizationhost"]
    : ["com.apple.systempreferences", "com.apple.authorizationhost", "com.apple.UserNotificationCenter"];
  if (!allowedApps.includes(frontBundle) || !codesignOK(frontPID, frontPath, frontBundle)) {
    return { error: errPrefix + "foreground_changed", blocking_pid: frontPID, blocking_bundle: frontBundle };
  }
  const disp = $.CGDisplayBounds($.CGMainDisplayID());
  const dx = disp.origin.x, dy = disp.origin.y, dw = disp.size.width, dh = disp.size.height;
  const arr = $.CGWindowListCopyWindowInfo($.kCGWindowListOptionOnScreenOnly | $.kCGWindowListExcludeDesktopElements, $.kCGNullWindowID);
  const count = $.CFArrayGetCount(arr);
  const windows = [];
  for (let i = 0; i < count; i++) {
    const d = ObjC.castRefToObject($.CFArrayGetValueAtIndex(arr, i));
    const alpha = d.objectForKey("kCGWindowAlpha").isNil() ? 1 : Number(ObjC.unwrap(d.objectForKey("kCGWindowAlpha")));
    if (alpha <= 0) continue;
    const b = d.objectForKey("kCGWindowBounds");
    if (b.isNil()) continue;
    const bx = Number(ObjC.unwrap(b.objectForKey("X")));
    const by = Number(ObjC.unwrap(b.objectForKey("Y")));
    const bw = Number(ObjC.unwrap(b.objectForKey("Width")));
    const bh = Number(ObjC.unwrap(b.objectForKey("Height")));
    if (bw <= 0 || bh <= 0) continue;
    const owner = Number(ObjC.unwrap(d.objectForKey("kCGWindowOwnerPID")));
    const winID = Number(ObjC.unwrap(d.objectForKey("kCGWindowNumber")));
    const layer = Number(ObjC.unwrap(d.objectForKey("kCGWindowLayer")));
    const oApp = $.NSRunningApplication.runningApplicationWithProcessIdentifier(owner);
    const oBid = oApp.isNil() ? "" : (ObjC.unwrap(oApp.bundleIdentifier) || "");
    const oPath = oApp.isNil() || oApp.bundleURL.isNil() ? "" : ObjC.unwrap(oApp.bundleURL.path);
    const fullDisp = bx === dx && by === dy && bw === dw && bh === dh;
    const isCompositor = layer > 0 && fullDisp && ((oBid === "com.apple.dock" && layer === 20) || (oBid === "com.apple.notificationcenterui" && layer === 23)) && codesignOK(owner, oPath, oBid);
    const isCursor = !oBid && layer >= 2147483600 && bw <= 64 && bh <= 64;
    windows.push({ x: bx, y: by, w: bw, h: bh, pid: owner, win: winID, layer, bundle: oBid, path: oPath, systemSurface: isCompositor || isCursor });
  }
  if (!passwordMode) {
    const covering = [];
    for (const w of windows) {
      const isTarget = w.pid === frontPID || (w.bundle === "com.apple.UserNotificationCenter" && codesignOK(w.pid, w.path, w.bundle));
      if (isTarget && w.w >= 100 && w.h >= 60) {
        const rx = Math.max(w.x, dx), ry = Math.max(w.y, dy);
        const rw = Math.min(w.x + w.w, dx + dw) - rx;
        const rh = Math.min(w.y + w.h, dy + dh) - ry;
        if (rw < 80 || rh < 40) return { error: "maintenance_window_unavailable" };
        for (const c of covering) {
          if (c.x < rx + rw && c.x + c.w > rx && c.y < ry + rh && c.y + c.h > ry) {
            return { error: "maintenance_window_obscured", blocking_pid: c.pid, blocking_window: c.win, blocking_bundle: c.bundle };
          }
        }
        return { version: 1, session, user, pid: w.pid, window: w.win, bundle: w.bundle, password_focused: false, rect: [rx, ry, rw, rh], display: [dx, dy, dw, dh] };
      }
      if (w.pid !== frontPID && !w.systemSurface) covering.push(w);
    }
    return { error: "maintenance_window_unavailable" };
  }
  const idx = windows.findIndex(w => w.pid === frontPID && w.layer === 0 && w.w >= 80 && w.h >= 40);
  if (idx < 0) return { error: "setup_password_window_unavailable" };
  const target = windows[idx];
  const accessibility = Boolean($.AXIsProcessTrusted());
  if (target.win === 0 || target.x < dx || target.y < dy || target.x + target.w > dx + dw || target.y + target.h > dy + dh) {
    return { error: "setup_password_window_unavailable" };
  }
  if (!accessibility && frontBundle === "com.apple.systempreferences") {
    const hasParent = windows.slice(idx + 1).some(w =>
      w.pid === frontPID && w.layer === 0 &&
      w.x <= target.x && w.y <= target.y && w.x + w.w >= target.x + target.w && w.y + w.h >= target.y + target.h &&
      w.w > target.w && w.h > target.h && target.w * target.h < w.w * w.h * 0.75
    );
    if (!hasParent) return { error: "setup_password_window_unavailable" };
  }
  for (let i = 0; i < idx; i++) {
    const c = windows[i];
    if (!c.systemSurface && c.x < target.x + target.w && c.x + c.w > target.x && c.y < target.y + target.h && c.y + c.h > target.y) {
      return { error: "setup_password_window_obscured" };
    }
  }
  const focused = accessibility && passwordFocused(frontPID, target.x, target.y, target.w, target.h);
  const nowFront = $.NSWorkspace.sharedWorkspace.frontmostApplication;
  if (nowFront.isNil() || nowFront.processIdentifier !== frontPID || activeSession(user) !== session) {
    return { error: "setup_password_foreground_changed" };
  }
  return {
    version: 1, session, user, pid: frontPID, window: target.win, bundle: frontBundle,
    rect: [target.x, target.y, target.w, target.h], display: [dx, dy, dw, dh],
    accessibility, password_focused: focused, selection_required: !accessibility
  };
}

function main(passwordMode) {
  const stdin = $.NSFileHandle.fileHandleWithStandardInput;
  const stdout = $.NSFileHandle.fileHandleWithStandardOutput;
  let buf = "";
  while (true) {
    let line = null;
    while (true) {
      const nl = buf.indexOf("\n");
      if (nl >= 0) { line = buf.slice(0, nl); buf = buf.slice(nl + 1); break; }
      let d;
      try { d = stdin.availableData; } catch (e) { return; }
      if (!d || Number(d.length) === 0) {
        if (buf.length > 0) { line = buf; buf = ""; break; }
        return;
      }
      const chunk = ObjC.unwrap($.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding));
      if (!chunk) return;
      buf += chunk;
    }
    let out = null;
    try {
      const req = JSON.parse(line);
      if (!req || Array.isArray(req) || typeof req !== "object" || (Object.keys(req).length !== 0 && !(Object.keys(req).length === 1 && req.action === "probe"))) {
        out = { error: "setup_password_probe_request_invalid" };
      } else {
        out = runProbe(passwordMode);
      }
    } catch (e) {
      out = { error: "setup_password_probe_request_invalid" };
    }
    stdout.writeData($(JSON.stringify(out) + "\n").dataUsingEncoding($.NSUTF8StringEncoding));
  }
}
main(PROBE_PASSWORD_MODE);
void 0;
`

func (s *loginSession) openCompositorProbe(timeout time.Duration, passwordMode bool) (*passwordProbe, error) {
	admin, user, err := s.maintenanceIdentity(false)
	if err != nil {
		return nil, err
	}
	script := strings.Replace(macOSCompositorProbeJXA, "PROBE_PASSWORD_MODE", func() string {
		if passwordMode {
			return "true"
		}
		return "false"
	}(), 1)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	inner := `uid=$(/usr/bin/id -u ` + shellescape.Quote(user) + `)
test "$(/usr/bin/stat -f %u /dev/console)" = "$uid" || exit 73
exec /bin/launchctl asuser "$uid" /usr/bin/sudo -Hu ` + shellescape.Quote(user) + ` /usr/bin/env -i HOME=` + shellescape.Quote("/Users/"+user) + ` PATH=/usr/bin:/bin:/usr/sbin /usr/bin/osascript -l JavaScript -e ` + shellescape.Quote(script)
	command, err := guestAdminRootCommand(ctx, s.profile, admin, inner)
	if err != nil {
		cancel()
		return nil, err
	}
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		cancel()
		return nil, err
	}
	if err = command.Start(); err != nil {
		input.Close()
		output.Close()
		cancel()
		return nil, err
	}
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 32<<10)
	return &passwordProbe{command: command, input: input, output: output, scanner: scanner, cancel: cancel, user: user, usedFallback: true}, nil
}

func maintenanceFailure(surface maintenanceWindow, err error, closed bool) reply {
	result := reply{Closed: closed, Error: err.Error()}
	if surface.Error == "component_update_required" {
		result.Recovery = "environment-update"
	} else if surface.Error == "requires_gui_login" {
		result.Recovery = "guest-login"
	}
	return result
}

func (s *loginSession) handleMaintenance(in request) (result reply) {
	defer func() { result.MaintenanceVersion = 1 }()
	if in.Setup || !guestos.ValidMacMaintenancePurpose(in.Maintenance) || len(in.Geometry) > 64 {
		return reply{Closed: true, Error: "维护用途无效"}
	}
	if in.Action == "open" {
		s.close()
		s.maintenance = in.Maintenance
		surface, err := s.maintenanceProbe(true)
		if err != nil {
			s.close()
			return maintenanceFailure(surface, err, true)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			surface, err = s.maintenanceProbe(false)
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			s.close()
			return maintenanceFailure(surface, err, true)
		}
		s.token, s.screenID = rand.Text(), "maintenance-"+surface.Session
		s.expires = time.Now().Add(5 * time.Minute)
		s.surface.Enable(true)
		return reply{Session: s.token, Administrator: s.maintenanceAdministrator}
	}
	if s.token == "" || s.maintenance != in.Maintenance || subtle.ConstantTimeCompare([]byte(in.Session), []byte(s.token)) != 1 {
		return reply{Closed: true}
	}
	if in.Action == "close" || time.Now().After(s.expires) {
		s.close()
		return reply{Closed: true}
	}
	surface, err := s.maintenanceProbe(false)
	if err != nil || s.screenID != "maintenance-"+surface.Session {
		s.close()
		if err == nil {
			err = errors.New("客机登录会话已变化，请重新打开维护画面")
		}
		return maintenanceFailure(surface, err, true)
	}
	if in.Action == "frame" {
		region := surface.region()
		frame, err := s.surface.Image(region[:])
		if err != nil {
			return reply{Error: "正在等待系统设置窗口画面"}
		}
		after, err := s.maintenanceProbe(false)
		if err != nil {
			s.close()
			return maintenanceFailure(after, err, true)
		}
		if after != surface {
			return reply{Error: "授权窗口已变化，正在刷新画面"}
		}
		s.maintenanceFrame = surface.geometry()
		return reply{Image: frame, MIME: "image/jpeg", Geometry: s.maintenanceFrame, Region: region[:]}
	}
	if in.Geometry == "" || in.Geometry != s.maintenanceFrame || in.Geometry != surface.geometry() {
		return reply{Error: "授权窗口已变化，请等待新画面后重试"}
	}
	switch in.Action {
	case "fill-password":
		if err := s.fillMaintenancePassword(surface); err != nil {
			return reply{Closed: s.token == "", Error: err.Error()}
		}
	case "select-all":
		s.passwordSelection = passwordSelection{}
		if !s.surface.SelectAll() {
			return reply{Error: "授权窗口尚未准备好"}
		}
	case "click":
		s.passwordSelection = passwordSelection{}
		if !surface.contains(in.X, in.Y) || !s.surface.Click(in.X, in.Y) {
			return reply{Error: "点击位置超出当前授权窗口"}
		}
		if probe, err := s.openMaintenancePasswordProbe(); err == nil {
			target, err := probe.target()
			if err == nil {
				s.passwordSelection.selectMaintenance(surface, target, probe.user, in.X, in.Y, time.Now())
			}
			probe.close()
		}
	case "key":
		s.passwordSelection = passwordSelection{}
		navigation := in.Code >= 123 && in.Code <= 126 || in.Code == 116 || in.Code == 121
		if in.Code < 0 || (in.Code > 53 && !navigation) || !s.surface.Key(in.Code, in.Shift) {
			return reply{Error: "此按键不能用于授权窗口"}
		}
	case "scroll":
		s.passwordSelection = passwordSelection{}
		if !surface.contains(in.X, in.Y) || in.DeltaX < -512 || in.DeltaX > 512 || in.DeltaY < -512 || in.DeltaY > 512 ||
			!s.surface.Scroll(in.X, in.Y, in.DeltaX, in.DeltaY) {
			return reply{Error: "滚动位置超出当前授权窗口"}
		}
	default:
		return reply{Error: "维护操作无效"}
	}
	return reply{}
}

func (s *loginSession) openMaintenancePasswordProbe() (*passwordProbe, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	command, user, err := s.maintenanceCommand(ctx, "--maintenance-password-probe")
	if err != nil {
		cancel()
		return nil, err
	}
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		cancel()
		return nil, err
	}
	if err = command.Start(); err != nil {
		input.Close()
		output.Close()
		cancel()
		return nil, err
	}
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 32<<10)
	return &passwordProbe{
		command:  command,
		input:    input,
		output:   output,
		scanner:  scanner,
		cancel:   cancel,
		user:     user,
		fallback: func() (*passwordProbe, error) { return s.openCompositorProbe(20*time.Second, true) },
	}, nil
}

func (s *loginSession) fillMaintenancePassword(window maintenanceWindow) error {
	selected := s.passwordSelection
	s.passwordSelection = passwordSelection{}
	probe, err := s.openMaintenancePasswordProbe()
	if err != nil {
		return err
	}
	defer probe.close()
	target, err := probe.target()
	if err != nil {
		return err
	}
	selection, permitted := selected.consumeMaintenance(window, target, probe.user, time.Now())
	if !permitted {
		return errors.New("请先选中系统授权窗口的密码框，再点击填写管理员密码")
	}
	password, err := s.maintenancePassword()
	if err != nil {
		return err
	}
	defer func() { clear(password) }()
	sequence, valid := passwordKeys(string(bytes.TrimRight(password, "\r\n")))
	if !valid {
		return errors.New("安装管理员凭据格式无效，请检查安装记录")
	}
	check := func() error {
		current, err := probe.target()
		if err != nil {
			return err
		}
		if time.Now().After(s.expires) || s.screenID != "maintenance-"+current.Session {
			s.close()
			return errors.New("客机授权会话已结束，请重新打开维护画面")
		}
		if !window.permitsPassword(current, selection, probe.user, time.Now()) {
			return errors.New("系统授权窗口或密码框已变化，填写已停止，请重新选中密码框")
		}
		return nil
	}
	if err = check(); err != nil {
		return err
	}
	if !target.Accessibility && !s.surface.Click(selection.X, selection.Y) {
		return errors.New("所选密码框已变化，请重新点选")
	}
	if err = check(); err != nil {
		return err
	}
	if !s.surface.SelectAll() {
		return errors.New("系统密码框尚未准备好，请重试")
	}
	for _, key := range sequence {
		if err = check(); err != nil {
			return err
		}
		if !s.surface.Key(key.code, key.shift) {
			return errors.New("管理员密码未能填写，请重新选中密码框后重试")
		}
	}
	return nil
}

func (s *loginSession) maintenancePassword() ([]byte, error) {
	user, err := guestos.MacOSProvisionUser(s.profile)
	if err != nil || user != s.maintenanceAdministrator {
		return nil, errors.New("客机安装身份已变化，请重新打开维护画面")
	}
	args, err := guestos.MacOSSSHArgs(s.profile, user)
	if err != nil {
		return nil, err
	}
	script := `set -eu; p=` + shellescape.Quote("/Users/"+user+"/password") + `
test ! -L "$p" && test "$(/usr/bin/stat -f %u "$p")" = "$(/usr/bin/id -u)"
mode=$(/usr/bin/stat -f %Lp "$p"); test "$((0$mode & 077))" = 0
exec /bin/cat "$p"`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", append(args, "-T", "cage-macos", "--", "exec /bin/sh -c "+shellescape.Quote(script))...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	pipe, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		return nil, errors.New("安装管理员凭据暂时不可用")
	}
	data, readErr := io.ReadAll(io.LimitReader(pipe, 1025))
	if readErr != nil || len(data) > 1024 {
		cancel()
	}
	if err = cmd.Wait(); err != nil || readErr != nil || len(data) == 0 || len(data) > 1024 {
		clear(data)
		return nil, errors.New("安装管理员凭据不可用，请核对安装记录")
	}
	return data, nil
}
