import { lazy, Suspense, type ReactNode } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router';
import { AppLayout } from './components/Layout';
import { Spinner } from './components/ui';
import { useAuth } from './lib/auth';
import { ActivityPage } from './pages/Activity';
import { AdminPage } from './pages/Admin';
import { ForgotPasswordPage, LoginPage, RegisterPage, ResetPasswordPage } from './pages/Auth';
import { CredentialsPage } from './pages/Credentials';
import { DashboardPage } from './pages/Dashboard';
import { DocumentDetailPage } from './pages/DocumentDetail';
import { DocumentsPage } from './pages/Documents';
import { LandingPage } from './pages/Landing';
import { LinksPage } from './pages/Links';
import { NotFoundPage } from './pages/NotFound';
import { QrScannerPage } from './pages/QrScanner';
import { OrgInboxViewPage, OrganizationPage } from './pages/Organization';
import { RecipientPage } from './pages/Recipient';
import { SettingsPage } from './pages/Settings';
import { SharePage } from './pages/Share';
import { UploadPage } from './pages/Upload';
import { VerifyPage } from './pages/Verify';

// Charts (recharts) load only when the analytics page is opened.
const AnalyticsPage = lazy(() => import('./pages/Analytics').then((m) => ({ default: m.AnalyticsPage })));

function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Spinner />;
  if (!me) return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  return <>{children}</>;
}

function RequireAdmin({ children }: { children: ReactNode }) {
  const { me } = useAuth();
  if (me?.user.role !== 'admin') return <Navigate to="/app" replace />;
  return <>{children}</>;
}

function GuestOnly({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth();
  if (loading) return <Spinner />;
  if (me) return <Navigate to="/app" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<GuestOnly><LoginPage /></GuestOnly>} />
        <Route path="/register" element={<GuestOnly><RegisterPage /></GuestOnly>} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="/s/:token" element={<RecipientPage />} />

        <Route path="/app" element={<RequireAuth><AppLayout /></RequireAuth>}>
          <Route index element={<DashboardPage />} />
          <Route path="documents" element={<DocumentsPage />} />
          <Route path="documents/upload" element={<UploadPage />} />
          <Route path="documents/:id" element={<DocumentDetailPage />} />
          <Route path="documents/:id/share" element={<SharePage />} />
          <Route path="links" element={<LinksPage />} />
          <Route path="analytics" element={<Suspense fallback={<Spinner />}><AnalyticsPage /></Suspense>} />
          <Route path="verify" element={<VerifyPage />} />
          <Route path="scan" element={<QrScannerPage />} />
          <Route path="activity" element={<ActivityPage />} />
          <Route path="credentials" element={<CredentialsPage />} />
          <Route path="org" element={<OrganizationPage />} />
          <Route path="org/inbox/:id" element={<OrgInboxViewPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="admin" element={<RequireAdmin><AdminPage /></RequireAdmin>} />
          <Route path="*" element={<NotFoundPage inApp />} />
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  );
}
