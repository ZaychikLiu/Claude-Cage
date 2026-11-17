package workbench

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/sylvinus/agent-vm/internal/cage"
	"github.com/sylvinus/agent-vm/internal/guestos"
)

// macOSPermissionsStatus describes automatic guest permission and helper diagnostics.
type macOSPermissionsStatus struct {
	Ready         bool                 `json:"ready"`
	Summary       string               `json:"summary"`
	Administrator string               `json:"administrator,omitempty"`
	AdHoc         bool                 `json:"ad_hoc,omitempty"`
	Checks        []screenSharingCheck `json:"checks"`
}

type macOSPermissionProbe struct {
	SetupReady                bool
	SetupError                string
	Screen                    bool
	Input                     bool
	ProjectInstallRequired    bool
	EnvironmentUpdateRequired bool
	Administrator             string
	GuestUser                 string
	GuestIsAdmin              bool
	HelperPaths               []string
	TeamID                    string
	Signature                 string
	CDHash                    string
	AutoLoginScreenLocked     bool
	HostProbeError            string
}

func (s *Server) macOSPermissions(w http.ResponseWriter, r *http.Request) {
	if s.macosGuest == nil {
		requestError(w, errScreenSharingNotMacOS)
		return
	}
	if !s.hasTrustedView(r) {
		http.Error(w, errScreenSharingNeedMacHost.Error(), http.StatusForbidden)
		return
	}
	s.mu.Lock()
	ready, closing := s.ready, s.closing
	updateRequired := s.guestUpdateRequired
	s.mu.Unlock()
	if !ready || closing {
		requestError(w, errScreenSharingNotReady)
		return
	}
	probe := macOSPermissionProbe{
		EnvironmentUpdateRequired: updateRequired,
		GuestUser:                 s.macosGuest.User,
	}
	if admin, err := guestos.MacOSProvisionUser(s.profile); err == nil {
		probe.Administrator = admin
	}
	data, err := s.macOSWindowCall(r.Context(), macOSWindowRequest{Action: "setup-status"})
	if err != nil {
		probe.HostProbeError = err.Error()
	} else {
		var status macSetupPermissions
		if json.Unmarshal(data, &status) != nil {
			probe.HostProbeError = "无法解析客机窗口状态"
		} else if status.Error != "" {
			probe.SetupError = status.Error
		} else {
			probe.SetupReady = true
			probe.Screen = status.Screen
			probe.Input = status.Input
			probe.ProjectInstallRequired = status.ProjectInstallRequired
		}
	}
	if s.vmRunning() {
		s.fillMacOSPermissionGuestProbe(r.Context(), &probe)
	}
	jsonReply(w, assembleMacOSPermissionStatus(probe))
}

func (s *Server) fillMacOSPermissionGuestProbe(ctx context.Context, probe *macOSPermissionProbe) {
	// Read-only guest inspection: helper copies, codesign identity/CDHash,
	// non-admin isolation, and leftover autoLoginUserScreenLocked plist key.
	script := `set -u
echo "ADMIN=$([[ " $(id -Gn) " == *" admin "* ]] && echo 1 || echo 0)"
echo "LOCKED=$(/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow autoLoginUserScreenLocked 2>/dev/null || echo 0)"
echo "PATHS_BEGIN"
/usr/bin/find /Applications "$HOME" -maxdepth 3 -iname "*Cage Guest Window*.app" 2>/dev/null || true
echo "PATHS_END"
echo "SIGN_BEGIN"
/usr/bin/codesign -dv "/Applications/Cage Guest Window.app" 2>&1 || true
echo "SIGN_END"`
	out, err := s.guest(ctx, script)
	if err != nil {
		if probe.HostProbeError == "" {
			probe.HostProbeError = err.Error()
		}
		return
	}
	section := ""
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		switch line {
		case "PATHS_BEGIN":
			section = "paths"
			continue
		case "SIGN_BEGIN":
			section = "sign"
			continue
		case "PATHS_END", "SIGN_END":
			section = ""
			continue
		}
		switch section {
		case "paths":
			if line != "" {
				probe.HelperPaths = append(probe.HelperPaths, line)
			}
		case "sign":
			if v, ok := strings.CutPrefix(line, "TeamIdentifier="); ok {
				probe.TeamID = strings.TrimSpace(v)
			} else if v, ok := strings.CutPrefix(line, "Signature="); ok {
				probe.Signature = strings.TrimSpace(v)
			} else if v, ok := strings.CutPrefix(line, "CDHash="); ok {
				probe.CDHash = strings.TrimSpace(v)
			}
		default:
			if v, ok := strings.CutPrefix(line, "ADMIN="); ok {
				probe.GuestIsAdmin = v == "1"
			} else if v, ok := strings.CutPrefix(line, "LOCKED="); ok {
				probe.AutoLoginScreenLocked = v == "1" || strings.EqualFold(v, "true")
			}
		}
	}
}

func assembleMacOSPermissionStatus(p macOSPermissionProbe) macOSPermissionsStatus {
	adminName := p.Administrator
	if adminName == "" {
		adminName = "cageprovision"
	}
	adhoc := p.Signature == "adhoc" || strings.EqualFold(p.TeamID, "not set")
	readdHint := ""
	if adhoc {
		readdHint = "（当前组件为 ad-hoc 签名：若更新或重编 Cage 后系统设置里的开关看起来已打开但仍提示未通过，说明 macOS 仍绑定在旧 CDHash。请在列表中选中 Cage Guest Window → 点左下角「-」删除旧项 → 点「+」重新选择 /Applications/Cage Guest Window.app 并开启，如提示 Quit & Reopen 请确认。）"
	}
	adminHint := fmt.Sprintf("请点击下方 Cage 自带的授权按钮操作（不要直接通过原生屏幕共享猜密码）；系统要求管理员时用户名填 %s，点选密码框后点顶部「填写管理员密码」。若提示“授权窗口被遮挡（如 screencapture）”，可切回原生屏幕共享按一次 Esc 取消截图选区。", adminName)

	screenCheck := screenSharingCheck{ID: "screen", Title: "屏幕录制权限（Cage Guest Window）", State: cage.CheckUnknown}
	inputCheck := screenSharingCheck{ID: "input", Title: "辅助功能权限（Cage Guest Window）", State: cage.CheckUnknown}
	switch {
	case p.SetupError == "requires_gui_login":
		msg := "客机尚未登录并解锁图形桌面，暂时无法读取屏幕录制与辅助功能状态。"
		remedy := "先在工作台点「查看客机登录界面」解锁桌面后再重新检查。"
		screenCheck.Evidence, screenCheck.Remedy = msg, remedy
		inputCheck.Evidence, inputCheck.Remedy = msg, remedy
	case p.HostProbeError != "" && !p.SetupReady:
		msg := "暂未连接到 Cage Guest Window：" + p.HostProbeError
		remedy := "等待客机启动完成或同步环境组件后点击「重新检查客机权限」。"
		screenCheck.Evidence, screenCheck.Remedy = msg, remedy
		inputCheck.Evidence, inputCheck.Remedy = msg, remedy
	default:
		if p.Screen {
			screenCheck.State = cage.CheckPassed
			screenCheck.Evidence = "Cage Guest Window 已获得屏幕录制权限，可实时读取 Claude Desktop 与浏览器窗口画面。"
		} else {
			screenCheck.State = cage.CheckFailed
			screenCheck.Evidence = "Cage Guest Window 尚未获得屏幕录制权限（screen=false）。"
			screenCheck.Remedy = "点击「屏幕录制权限」开启 Cage Guest Window 开关。" + adminHint + readdHint
		}
		if p.Input {
			inputCheck.State = cage.CheckPassed
			inputCheck.Evidence = "Cage Guest Window 已获得辅助功能权限，可正常发送鼠标与键盘操作。"
		} else {
			inputCheck.State = cage.CheckFailed
			inputCheck.Evidence = "Cage Guest Window 尚未获得辅助功能权限（input=false）。"
			inputCheck.Remedy = "点击「辅助功能权限」开启 Cage Guest Window 开关。" + adminHint + readdHint
		}
	}

	helperCheck := screenSharingCheck{ID: "window-helper", Title: "客机窗口组件与签名", State: cage.CheckPassed}
	var duplicates []string
	for _, path := range p.HelperPaths {
		if path != "/Applications/Cage Guest Window.app" {
			duplicates = append(duplicates, path)
		}
	}
	sigDesc := "未读到签名"
	if p.Signature != "" || p.TeamID != "" {
		sigParts := []string{}
		if p.Signature != "" {
			sigParts = append(sigParts, p.Signature)
		}
		if p.TeamID != "" {
			sigParts = append(sigParts, "Team="+p.TeamID)
		}
		if p.CDHash != "" {
			cd := p.CDHash
			if len(cd) > 12 {
				cd = cd[:12]
			}
			sigParts = append(sigParts, "CDHash="+cd)
		}
		sigDesc = strings.Join(sigParts, " / ")
	}
	switch {
	case p.EnvironmentUpdateRequired:
		helperCheck.State = cage.CheckFailed
		helperCheck.Evidence = "客机环境组件版本与当前 Cage 不一致。"
		helperCheck.Remedy = "先保存工作，点击上方的「同步环境组件」完成更新；若本次更换为 ad-hoc 签名构建，更新后需在两个权限列表里先「-」删旧项再「+」重加。"
	case len(duplicates) > 0:
		helperCheck.State = cage.CheckFailed
		helperCheck.Evidence = "客机中发现多个 Cage Guest Window.app 副本：" + strings.Join(duplicates, "、")
		helperCheck.Remedy = "保留唯一的 /Applications/Cage Guest Window.app 并移除旧备份副本，否则 macOS TCC 可能继续匹配旧副本签名。"
	case len(p.HelperPaths) == 0 && p.HostProbeError == "":
		helperCheck.State = cage.CheckFailed
		helperCheck.Evidence = "客机中未找到 /Applications/Cage Guest Window.app。"
		helperCheck.Remedy = "点击上方「同步环境组件」重新安装客机组件。"
	default:
		helperCheck.Evidence = "已安装唯一的 /Applications/Cage Guest Window.app（" + sigDesc + "）。"
		if adhoc {
			helperCheck.Evidence += " 当前为 ad-hoc 本地签名，更新 Cage 后若权限失效需在系统设置中「-」删旧再「+」重加。"
		}
	}

	sessionCheck := screenSharingCheck{ID: "guest-session", Title: "普通账户隔离与自动登录", State: cage.CheckPassed}
	guestName := p.GuestUser
	if guestName == "" {
		guestName = "当前客机账户"
	}
	if p.GuestIsAdmin {
		sessionCheck.State = cage.CheckFailed
		sessionCheck.Evidence = fmt.Sprintf("客机账户 %s 意外拥有 admin 权限，不符合 Cage 隔离要求。", guestName)
		sessionCheck.Remedy = "日常客机账户应保持普通用户，系统授权通过托管管理员账户完成。"
	} else if p.AutoLoginScreenLocked {
		sessionCheck.State = cage.CheckFailed
		sessionCheck.Evidence = "检测到 /Library/Preferences/com.apple.loginwindow 存在 autoLoginUserScreenLocked=1，冷启动会自动锁定并停在登录画面。"
		sessionCheck.Remedy = "若不需要每次开机停在锁屏界面（常见于 macOS 系统大版本升级残留），可使用管理员身份删除 autoLoginUserScreenLocked 键后再重启。"
	} else {
		sessionCheck.Evidence = fmt.Sprintf("日常客机账户 %s 为普通标准用户（非管理员，符合安全隔离），系统管理员由 %s 托管；未检测到残留的自动锁屏键。", guestName, adminName)
	}

	checks := []screenSharingCheck{screenCheck, inputCheck, helperCheck, sessionCheck}
	failed := 0
	pending := 0
	for _, item := range checks {
		if item.State == cage.CheckFailed {
			failed++
		} else if item.State != cage.CheckPassed {
			pending++
		}
	}
	allReady := failed == 0 && pending == 0
	summary := "全部 4 项客机权限与组件检查均已通过，Claude Desktop 与客机浏览器可正常显示并操作。"
	if !allReady {
		summary = fmt.Sprintf("检测到 %d 项未通过、%d 项待确认，请按下方指引操作后点击「重新检查客机权限」。", failed, pending)
	}
	return macOSPermissionsStatus{
		Ready:         allReady,
		Summary:       summary,
		Administrator: adminName,
		AdHoc:         adhoc,
		Checks:        checks,
	}
}
