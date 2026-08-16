import { useEffect, useState } from "react";
import { api, type Bookmark, type BookmarkInput } from "../api";

const BLANK: BookmarkInput = { label: "", address: "", password: "" };

export function BookmarksTab({ onError }: { onError: (error: string) => void }) {
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [draft, setDraft] = useState<BookmarkInput>(BLANK);
  const [editing, setEditing] = useState<number | null>(null);

  useEffect(() => {
    api.bookmarks().then(setBookmarks).catch((e) => onError(String(e)));
  }, [onError]);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!draft.label.trim() || !draft.address.trim()) return;

    const done = (next: Bookmark[]) => {
      setBookmarks(next);
      setDraft(BLANK);
      setEditing(null);
    };

    const request =
      editing === null ? api.addBookmark(draft) : api.updateBookmark(editing, draft);
    request.then(done).catch((e) => onError(String(e)));
  };

  const edit = (bookmark: Bookmark) => {
    setEditing(bookmark.id);
    setDraft({
      label: bookmark.label,
      address: bookmark.address,
      password: bookmark.password ?? "",
      identity: bookmark.identity,
    });
  };

  return (
    <div className="settings-pane">
      {bookmarks.length === 0 ? (
        <p className="muted">No saved servers yet.</p>
      ) : (
        <ul className="bookmark-list">
          {bookmarks.map((bookmark) => (
            <li key={bookmark.id}>
              <div className="bookmark-main">
                <strong>{bookmark.label}</strong>
                <span className="muted">{bookmark.address}</span>
              </div>
              {bookmark.password !== undefined && (
                <span className="muted" title="A password is saved for this server">
                  🔑
                </span>
              )}
              <button className="linklike" onClick={() => edit(bookmark)}>
                edit
              </button>
              <button
                className="linklike"
                onClick={() =>
                  api
                    .removeBookmark(bookmark.id)
                    .then(setBookmarks)
                    .catch((e) => onError(String(e)))
                }
              >
                remove
              </button>
            </li>
          ))}
        </ul>
      )}

      <form className="bookmark-form" onSubmit={submit}>
        <strong>{editing === null ? "Add a server" : "Edit server"}</strong>
        <label>
          Name
          <input
            value={draft.label}
            onChange={(e) => setDraft({ ...draft, label: e.target.value })}
            placeholder="What you call it"
          />
        </label>
        <label>
          Address
          <input
            value={draft.address}
            onChange={(e) => setDraft({ ...draft, address: e.target.value })}
            placeholder="hostname or IP, port optional"
          />
        </label>
        <label>
          Password <span className="muted">(only if the server has one)</span>
          <input
            type="password"
            value={draft.password ?? ""}
            onChange={(e) => setDraft({ ...draft, password: e.target.value })}
          />
        </label>
        <div className="row">
          <button type="submit">{editing === null ? "Add" : "Save"}</button>
          {editing !== null && (
            <button
              type="button"
              className="linklike"
              onClick={() => {
                setEditing(null);
                setDraft(BLANK);
              }}
            >
              cancel
            </button>
          )}
        </div>
      </form>

      <p className="muted">
        Removing a server here only forgets the shortcut. The identity it proved
        on first contact stays pinned, so a future connection is still checked
        against it.
      </p>
    </div>
  );
}
