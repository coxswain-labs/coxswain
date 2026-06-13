import { useState } from 'preact/hooks';

/**
 * Controlled tab bar + panel switcher.
 *
 * @param {{ id: string, label: string, content: JSX }[]} tabs
 * @param {string} [defaultTab] - id of the initially active tab.
 */
export function Tabs({ tabs, defaultTab }) {
  const [active, setActive] = useState(defaultTab ?? tabs[0]?.id);

  const handleKey = (id) => (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setActive(id);
    }
  };

  const current = tabs.find((t) => t.id === active);

  return (
    <>
      <div class="tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={t.id === active}
            class={`tab${t.id === active ? ' active' : ''}`}
            onClick={() => setActive(t.id)}
            onKeyDown={handleKey(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel">{current?.content}</div>
    </>
  );
}
