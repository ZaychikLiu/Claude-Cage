set -euo pipefail
domain=$1
locale=$2
language=${locale/_/-}
browser_language=${3:-}
browser_profile=${4:-$HOME/Library/Application Support/Cage/Browser}

current=$(/usr/bin/defaults read "$domain" AppleLocale 2>/dev/null || true)
if [[ ${current%%@*} != "$locale" ]]; then
  /usr/bin/defaults write "$domain" AppleLocale -string "$locale"
fi

languages=$(/usr/bin/defaults read "$domain" AppleLanguages 2>/dev/null || echo '()')
plist=$(/usr/bin/plutil -convert xml1 -o - - <<< "$languages")
first=$(/usr/bin/plutil -extract 0 raw -o - - <<< "$plist" 2>/dev/null || true)
if [[ "$first" != "$language" ]]; then
  preferred=("$language")
  i=0
  while previous=$(/usr/bin/plutil -extract "$i" raw -o - - <<< "$plist" 2>/dev/null); do
    if [[ "$previous" != "$language" ]]; then preferred+=("$previous"); fi
    i=$((i+1))
  done
  /usr/bin/defaults write "$domain" AppleLanguages -array "${preferred[@]}"
fi

if [[ -n "$browser_language" ]]; then
  chrome_prefs_state() {
    /usr/bin/osascript -l JavaScript - "$browser_profile" "$browser_language" "$1" <<'JXA'
ObjC.import("Foundation");
ObjC.import("stdio");
const fm = $.NSFileManager.defaultManager;

function readJSON(path) {
  if (!fm.fileExistsAtPath(path)) return null;
  const err = $();
  const str = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, err);
  if (!str || str.isNil()) {
    throw new Error("failed to read " + path);
  }
  return JSON.parse(ObjC.unwrap(str));
}

function run(argv) {
  const profileDir = argv[0];
  const lang = argv[1];
  const mode = argv[2];

  const localState = readJSON(profileDir + "/Local State");
  let active = (localState && localState.profile && localState.profile.last_used) || "Default";
  if (!/^(?:Default|Profile [0-9]+)$/.test(active)) {
    active = "Default";
  }

  const prefsDir = profileDir + "/" + active;
  const prefsPath = prefsDir + "/Preferences";
  const existing = readJSON(prefsPath);
  const prefs = existing === null ? {} : existing;
  if (prefs === null || typeof prefs !== "object" || Array.isArray(prefs)) {
    throw new Error("invalid Preferences object");
  }
  const intl = prefs.intl && typeof prefs.intl === "object" && !Array.isArray(prefs.intl) ? prefs.intl : {};
  const needsUpdate = intl.accept_languages !== lang || intl.selected_languages !== lang;
  if (mode === "check") {
    return needsUpdate ? "needs_update" : "ok";
  }
  if (!needsUpdate) {
    return "ok";
  }

  const dirAttrs = $.NSDictionary.dictionaryWithObjectForKey($(0o700), $.NSFilePosixPermissions);
  if (!fm.fileExistsAtPath(profileDir)) {
    fm.createDirectoryAtPathWithIntermediateDirectoriesAttributesError(profileDir, true, dirAttrs, $());
  }
  if (!fm.fileExistsAtPath(prefsDir)) {
    fm.createDirectoryAtPathWithIntermediateDirectoriesAttributesError(prefsDir, true, dirAttrs, $());
  }

  prefs.intl = Object.assign({}, intl, {
    accept_languages: lang,
    selected_languages: lang,
  });
  const tmpPath = prefsPath + ".cage-next-" + $.NSProcessInfo.processInfo.processIdentifier;
  const content = $(JSON.stringify(prefs));
  const data = content.dataUsingEncoding($.NSUTF8StringEncoding);
  const fileAttrs = $.NSDictionary.dictionaryWithObjectForKey($(0o600), $.NSFilePosixPermissions);
  if (!fm.createFileAtPathContentsAttributes(tmpPath, data, fileAttrs)) {
    throw new Error("failed to write " + tmpPath);
  }
  if ($.rename(tmpPath, prefsPath) !== 0) {
    fm.removeItemAtPathError(tmpPath, $());
    throw new Error("failed to rename " + tmpPath + " to " + prefsPath);
  }
  return "updated";
}
JXA
  }

  if [[ $(chrome_prefs_state check) == "needs_update" ]]; then
    pids=$(/bin/ps -axww -o pid=,args= | /usr/bin/awk -v prefix="--user-data-dir=$browser_profile" '
      index($0, "/Contents/MacOS/Google Chrome ") > 0 && index($0, "--type=") == 0 {
        pos = index($0, prefix)
        if (pos > 0) {
          after = substr($0, pos + length(prefix), 1)
          if (after == "" || after == " ") print $1
        }
      }
    ')
    if [[ -n "$pids" ]]; then
      while read -r pid; do
        [[ -n "$pid" ]] && /bin/kill -TERM "$pid" 2>/dev/null || true
      done <<< "$pids"
      for _ in $(seq 1 50); do
        still_running=0
        while read -r pid; do
          if [[ -n "$pid" ]] && /bin/kill -0 "$pid" 2>/dev/null; then
            still_running=1
            break
          fi
        done <<< "$pids"
        (( still_running == 0 )) && break
        /bin/sleep 0.1
      done
    fi
    chrome_prefs_state sync >/dev/null
  fi
fi
