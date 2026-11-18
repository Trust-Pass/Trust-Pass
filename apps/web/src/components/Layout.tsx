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
  QrCode,
  ScrollText,
  Settings,
  Shield,
} from 'lucide-react';
import { useState, type ReactNode } from 'react';
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
    { to: '/app/scan', label: 'QR Scanner', icon: <QrCode className="size-5" /> },
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

const BOTTOM_ITEMS = [
  { to: '/app', label: 'Home', icon: LayoutDashboard, end: true },
  { to: '/app/documents', label: 'Documents', icon: FileText },
  { to: '/app/links', label: 'Links', icon: Link2 },
  { to: '/app/analytics', label: 'Analytics', icon: BarChart3 },
];

export function AppLayout() {
  const me = useMe();
  const { logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

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

  return (
    <div className="min-h-dvh lg:pl-72">
      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 hidden w-72 flex-col bg-navy-900 px-4 py-5 lg:flex">
        <Link to="/app" className="mb-7 px-2">
          <Logo light />
        </Link>
        <div className="flex-1 overflow-y-auto">
          <SideNav />
        </div>
        {userBlock}
      </aside>

      {/* Top bar */}
      <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/90 backdrop-blur">
        <div className="page-pad flex h-14 items-center justify-between gap-3">
          <Link to="/app" className="lg:hidden">
            <Logo />
          </Link>
          <p className="hidden text-sm text-slate-500 lg:block">
            Signed in as <span className="font-medium text-navy-900">{me.user.email}</span>
            {me.user.role === 'admin' && <span className="ml-2 rounded-full bg-navy-900 px-2 py-0.5 text-xs font-medium text-white">Admin</span>}
          </p>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setNotificationsOpen(true)}
              className="relative rounded-xl p-2.5 text-navy-800 hover:bg-slate-100"
              aria-label={`Notifications${me.unreadNotifications ? `, ${me.unreadNotifications} unread` : ''}`}
            >
              <Bell className="size-5" />
              {me.unreadNotifications > 0 && (
                <span className="absolute top-1 right-1 flex min-w-4.5 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white">
                  {me.unreadNotifications > 9 ? '9+' : me.unreadNotifications}
                </span>
              )}
            </button>
            <button type="button" onClick={() => setMenuOpen(true)} className="rounded-xl p-2.5 text-navy-800 hover:bg-slate-100 lg:hidden" aria-label="Open menu">
              <Menu className="size-5" />
            </button>
          </div>
        </div>
      </header>

      <main key={location.pathname} className="page-pad mx-auto max-w-6xl pt-5 pb-28 sm:pt-7 lg:pb-12">
        <Outlet />
      </main>

      {/* Mobile bottom navigation */}
      <nav className="safe-bottom fixed inset-x-0 bottom-0 z-30 border-t border-slate-200 bg-white/95 backdrop-blur lg:hidden" aria-label="Quick">
        <div className="grid grid-cols-5">
          {BOTTOM_ITEMS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => clsx('flex h-16 flex-col items-center justify-center gap-1 text-[11px] font-medium', isActive ? 'text-teal-600' : 'text-slate-500')}
            >
              <Icon className="size-5" />
              {label}
            </NavLink>
          ))}
          <button type="button" onClick={() => setMenuOpen(true)} className="flex h-16 flex-col items-center justify-center gap-1 text-[11px] font-medium text-slate-500">
            <Menu className="size-5" />
            More
          </button>
        </div>
      </nav>

      {/* Mobile menu sheet */}
      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Menu">
          <button type="button" className="absolute inset-0 bg-navy-950/50" onClick={() => setMenuOpen(false)} aria-label="Close menu" />
          <div className="safe-bottom absolute inset-x-0 bottom-0 max-h-[88dvh] overflow-y-auto rounded-t-3xl bg-navy-900 px-4 pt-3 pb-4">
            <div className="mx-auto mb-4 h-1.5 w-10 rounded-full bg-white/20" />
            <SideNav onNavigate={() => setMenuOpen(false)} />
            <div className="mt-4">{userBlock}</div>
          </div>
        </div>
      )}

      <NotificationsPanel open={notificationsOpen} onClose={() => setNotificationsOpen(false)} />
    </div>
  );
}
