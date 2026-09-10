export default function Toast({ toast }) {
  if (!toast) return null;
  return (
    <div className={`sync-toast sync-toast--${toast.type} sync-toast--visible`} style={{ display: "block" }}>
      {toast.message}
    </div>
  );
}
