import React, { useState } from "react";
import { LoaderCircle, Monitor } from "lucide-react";
import { api } from "./api";
import "./initialization.css";

const labels = { passed: "已通过", failed: "未通过", unknown: "尚未完成" };

export function MacOSScreenSharingButton({
  label = "原生桌面",
  className,
  iconSize = 14,
  disabled = false,
  onStatus,
  onError,
}) {
  const [busy, setBusy] = useState(false);
  async function openNativeScreenSharing() {
    setBusy(true);
    try {
      await api("/environment/macos-screen-sharing", { action: "open" });
      onStatus?.("已打开原生屏幕共享");
    } catch (error) {
      onError?.(error.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <button
      type="button"
      className={className}
      disabled={disabled || busy}
      title="用 macOS 原生「屏幕共享」打开完整虚拟桌面（高清跟手、支持全屏切换；首次需在客机 系统设置 → 通用 → 共享 开启）"
      onClick={() => void openNativeScreenSharing()}
    >
      {busy ? <LoaderCircle size={iconSize} className="spin" /> : <Monitor size={iconSize} />}
      <span>{label}</span>
    </button>
  );
}

export function ScreenSharingChecks({ checks = [], summary, status }) {
  const items = checks.length ? checks : status?.checks || [];
  const text = summary || status?.summary;
  if (!text && items.length === 0) return null;
  return <>
    {text && <p role="status">{text}</p>}
    {items.length > 0 && <ol className="initialization-checks" aria-label="屏幕共享检查结果">
      {items.map(check => <li key={check.id}>
        <strong>{check.title} · {labels[check.state] || "尚未完成"}</strong>
        <p>{check.evidence}</p>
        {check.state !== "passed" && check.remedy && <p>{check.remedy}</p>}
      </li>)}
    </ol>}
  </>;
}
