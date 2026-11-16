import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  BadgeCheck,
  BarChart3,
  Bell,
  Building2,
  FileText,
  GraduationCap,
  LayoutDashboard,
  Link2,
  LogOut,
  Menu,
  ScrollText,
  Settings,
  Shield,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router';
import { api } from '../lib/api';
import { useAuth, useMe } from '../lib/auth';
import { initials, relativeTime } from '../lib/format';
import type { Notification } from '../lib/types';
import { Logo } from './Logo';
import { Button, EmptyState, Modal, Spinner } from './ui';

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  end?: boolean;
}

function useNavItems(): NavItem[] {
  const me = useMe();
  const items: NavItem[] = [
    { to: '/app', label: 'Dashboard', icon: <LayoutDashboard className="size-5" />, end: true },
    { to: '/app/documents', label: 'My documents', icon: <FileText className="size-5" /> },
    { to: '/app/links', label: 'Sharing links', icon: <Link2 className="size-5" /> },
    { to: '/app/analytics', label: 'Access analytics', icon: <BarChart3 className="size-5" /> },
    { to: '/app/verify', label: 'Verify a document', icon: <BadgeCheck className="size-5" /> },
    { to: '/app/activity', label: 'Activity log', icon: <ScrollText className="size-5" /> },
    { to: '/app/credentials', label: 'Demo University', icon: <GraduationCap className="size-5" /> },
  ];
  if (me.organizations.length > 0) items.push({ to: '/app/org', label: 'Organization', icon: <Building2 className="size-5" /> });
  if (me.user.role === 'admin') items.push({ to: '/app/admin', label: 'Admin', icon: <Shield className="size-5" /> });
  items.push({ to: '/app/settings', label: 'Settings', icon: <Settings className="size-5" /> });
  return items;
}

function SideNav({ onNavigate }: { onNavigate?: () => void }) {
  const items = useNavItems();
  return (
    <nav className="space-y-1" aria-label="Main">
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          onClick={onNavigate}
          className={({ isActive }) =>
            clsx(
              'flex h-11 items-center gap-3 rounded-xl px-3 text-[15px] font-medium transition-colors',
              isActive ? 'bg-white/10 text-white' : 'text-navy-200 hover:bg-white/5 hover:text-white',
            )
          }
        >
          {item.icon}
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}

function NotificationsPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { data, isLoading } = useQuery({
    queryKey: ['notifications'],
    queryFn: () => api<{ unread: number; notifications: Notification[] }>('/api/notifications'),
    enabled: open,
  });
  const readAll = useMutation({
    mutationFn: () => api('/api/notifications/read-all', { method: 'POST' }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['notifications'] });
      void queryClient.invalidateQueries({ queryKey: ['me'] });
    },
  });
  const markRead = useMutation({
    mutationFn: (id: string) => api(`/api/notifications/${id}/read`, { method: 'POST' }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['notifications'] });
      void queryClient.invalidateQueries({ queryKey: ['me'] });
    },
  });

  const openNotification = (n: Notification) => {
    if (!n.read) markRead.mutate(n.id);
    onClose();
    if (n.type === 'link_received') navigate('/app/org');
    else if (n.linkId) navigate('/app/links');
    else if (n.documentId) navigate(`/app/documents/${n.documentId}`);
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Notifications"
      footer={
        data && data.unread > 0 ? (
          <Button variant="secondary" onClick={() => readAll.mutate()} loading={readAll.isPending}>
            Mark all as read
          </Button>
        ) : undefined
      }
    >
      {isLoading ? (
        <Spinner />
      ) : !data || data.notifications.length === 0 ? (
        <EmptyState icon={<Bell className="size-6" />} title="No notifications yet" body="Security alerts about your links and documents will appear here." />
      ) : (
        <ul className="-mx-2 divide-y divide-slate-100">
          {data.notifications.map((n) => (
            <li key={n.id}>
              <button type="button" onClick={() => openNotification(n)} className="flex w-full gap-3 rounded-xl px-2 py-3 text-left hover:bg-slate-50">
                <span className={clsx('mt-1.5 size-2 shrink-0 rounded-full', n.read ? 'bg-transparent' : n.type.startsWith('alert') ? 'bg-amber-500' : 'bg-teal-500')} />
                <span className="min-w-0">
                  <span className="block text-sm font-semibold text-navy-950">{n.title}</span>
                  <span className="mt-0.5 block text-sm text-slate-600">{n.body}</span>
                  <span className="mt-1 block text-xs text-slate-400">{relativeTime(n.at)}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Modal>
  );
}

const SIDEBAR_PREF_KEY = 'trustpass.sidebar';

function readSidebarPref(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_PREF_KEY) !== 'closed';
  } catch {
    return true;
  }
}

function writeSidebarPref(open: boolean) {
  try {
    window.localStorage.setItem(SIDEBAR_PREF_KEY, open ? 'open' : 'closed');
  } catch {
    // Storage can be unavailable (private mode); the choice then lasts for this visit only.
  }
}

export function AppLayout() {
  const me = useMe();
  const { logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  // Mobile and tablet: the sidebar is a drawer that the menu button opens.
  const [drawerOpen, setDrawerOpen] = useState(false);
  // Desktop: the sidebar is docked; the menu button shows or hides it.
  const [dockedOpen, setDockedOpen] = useState(readSidebarPref);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  const closeDrawer = useCallback(() => setDrawerOpen(false), []);

  const toggleMenu = () => {
    if (window.matchMedia('(min-width: 1024px)').matches) {
      setDockedOpen((open) => {
        writeSidebarPref(!open);
        return !open;
      });
    } else {
      setDrawerOpen((open) => !open);
    }
  };

  // Close the drawer on navigation, on Escape and when the screen grows to desktop size.
  useEffect(() => {
    setDrawerOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setDrawerOpen(false);
    };
    const desktop = window.matchMedia('(min-width: 1024px)');
    const onResize = () => {
      if (desktop.matches) setDrawerOpen(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', onKey);
    desktop.addEventListener('change', onResize);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', onKey);
      desktop.removeEventListener('change', onResize);
    };
  }, [drawerOpen]);

  const signOut = async () => {
    await logout();
    navigate('/login');
  };

  const userBlock = (
    <div className="flex items-center gap-3 rounded-xl bg-white/5 p-3">
      <div className="flex size-9 shrink-0 items-center justify-center rounded-full bg-teal-500 text-sm font-bold text-navy-950">{initials(me.user.fullName)}</div>
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-semibold text-white">{me.user.fullName}</p>
        <p className="truncate text-xs text-navy-300">{me.organizations[0]?.name ?? me.user.email}</p>
      </div>
      <button type="button" onClick={signOut} className="rounded-lg p-2 text-navy-300 hover:bg-white/10 hover:text-white" aria-label="Sign out">
        <LogOut className="size-4" />
      </button>
    </div>
  );

  const sidebarBody = (onNavigate?: () => void) => (
    <>
      <div className="flex-1 overflow-y-auto">
        <SideNav onNavigate={onNavigate} />
      </div>
      <div className="mt-4">{userBlock}</div>
    </>
  );

  const menuExpanded = drawerOpen || dockedOpen;

  return (
    <div className={clsx('min-h-dvh transition-[padding] duration-200', dockedOpen && 'lg:pl-72')}>
      {/* Desktop sidebar (docked). Hidden on smaller screens, where the drawer below is used. */}
      <aside
        id="app-sidebar"
        className={clsx(
          'fixed inset-y-0 left-0 z-20 hidden w-72 flex-col bg-navy-900 px-4 py-5 transition-transform duration-200 lg:flex',
          !dockedOpen && 'lg:-translate-x-full',
        )}
        inert={!dockedOpen}
        aria-label="Sidebar"
      >
        <Link to="/app" className="mb-7 px-2">
          <Logo light />
        </Link>
        {sidebarBody()}
      </aside>

      {/* Top bar: the only navigation bar, on every screen size. */}
      <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/90 backdrop-blur">
        <div className="page-pad flex h-14 items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            <button
              type="button"
              onClick={toggleMenu}
              className="-ml-2 rounded-xl p-2.5 text-navy-800 hover:bg-slate-100"
              aria-label={menuExpanded ? 'Close menu' : 'Open menu'}
              aria-controls="app-sidebar app-drawer"
              aria-expanded={menuExpanded}
            >
              <Menu className="size-5" />
            </button>
            <Link to="/app" className={clsx(dockedOpen && 'lg:hidden')}>
              <Logo />
            </Link>
          </div>
          <div className="flex min-w-0 items-center gap-3">
            <p className="hidden min-w-0 truncate text-sm text-slate-500 lg:block">
              Signed in as <span className="font-medium text-navy-900">{me.user.email}</span>
              {me.user.role === 'admin' && <span className="ml-2 rounded-full bg-navy-900 px-2 py-0.5 text-xs font-medium text-white">Admin</span>}
            </p>
            <button
              type="button"
              onClick={() => setNotificationsOpen(true)}
              className="relative -mr-2 rounded-xl p-2.5 text-navy-800 hover:bg-slate-100"
              aria-label={`Notifications${me.unreadNotifications ? `, ${me.unreadNotifications} unread` : ''}`}
            >
              <Bell className="size-5" />
              {me.unreadNotifications > 0 && (
                <span className="absolute top-1 right-1 flex min-w-4.5 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white">
                  {me.unreadNotifications > 9 ? '9+' : me.unreadNotifications}
                </span>
              )}
            </button>
          </div>
        </div>
      </header>

      <main key={location.pathname} className="page-pad mx-auto max-w-6xl pt-5 pb-12 sm:pt-7">
        <Outlet />
      </main>

      {/* Mobile and tablet sidebar (drawer from the left) */}
      <div className={clsx('fixed inset-0 z-40 lg:hidden', !drawerOpen && 'pointer-events-none')} inert={!drawerOpen}>
        <button
          type="button"
          tabIndex={-1}
          className={clsx('absolute inset-0 bg-navy-950/50 transition-opacity duration-200', drawerOpen ? 'opacity-100' : 'opacity-0')}
          onClick={closeDrawer}
          aria-label="Close menu"
        />
        <aside
          id="app-drawer"
          role="dialog"
          aria-modal="true"
          aria-label="Menu"
          className={clsx(
            'safe-bottom absolute inset-y-0 left-0 flex w-[min(18rem,85vw)] flex-col bg-navy-900 px-4 pt-3 pb-4 shadow-2xl transition-transform duration-200',
            drawerOpen ? 'translate-x-0' : '-translate-x-full',
          )}
        >
          <div className="mb-5 flex h-11 items-center justify-between">
            <Link to="/app" onClick={closeDrawer} className="px-2">
              <Logo light />
            </Link>
            <button type="button" onClick={closeDrawer} className="rounded-xl p-2.5 text-navy-200 hover:bg-white/10 hover:text-white" aria-label="Close menu">
              <X className="size-5" />
            </button>
          </div>
          {sidebarBody(closeDrawer)}
        </aside>
      </div>

      <NotificationsPanel open={notificationsOpen} onClose={() => setNotificationsOpen(false)} />
    </div>
  );
}
