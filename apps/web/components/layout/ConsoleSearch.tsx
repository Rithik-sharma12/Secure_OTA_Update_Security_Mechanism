'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { Search } from 'lucide-react';
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from '@/components/ui/command';

export type SearchGroup = { title: string; items: Array<{ label: string; href: string; icon: React.ReactNode }> };

/**
 * The round search button in the header (and Ctrl/⌘ + K): jump to any
 * console page by typing part of its name.
 */
export function ConsoleSearch({ groups }: { groups: SearchGroup[] }) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);

  React.useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.key === 'k' || event.key === 'K') && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <>
      <button type="button" className="ota-iconbtn gloss-iconbtn" aria-label="Search pages (Ctrl+K)" title="Search pages (Ctrl+K)" onClick={() => setOpen(true)}>
        <Search className="h-[18px] w-[18px]" />
      </button>
      <CommandDialog open={open} onOpenChange={setOpen} title="Search pages" description="Jump to a console page">
        <CommandInput placeholder="Search pages…" />
        <CommandList>
          <CommandEmpty>No page matches.</CommandEmpty>
          {groups.map((group) => (
            <CommandGroup key={group.title} heading={group.title}>
              {group.items.map((item) => (
                <CommandItem
                  key={item.href}
                  // Quiet highlight in the theme's tint instead of a solid accent block.
                  className="data-[selected=true]:bg-[color:var(--app-hover)] data-[selected=true]:text-foreground data-[selected=true]:shadow-[inset_2px_0_0_var(--ember)]"
                  value={`${group.title} ${item.label}`}
                  onSelect={() => {
                    setOpen(false);
                    router.push(item.href);
                  }}
                >
                  {item.icon}
                  {item.label}
                  <CommandShortcut>{group.title}</CommandShortcut>
                </CommandItem>
              ))}
            </CommandGroup>
          ))}
        </CommandList>
      </CommandDialog>
    </>
  );
}
