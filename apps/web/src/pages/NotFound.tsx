import { Compass } from 'lucide-react';
import { ButtonLink, EmptyState } from '../components/ui';

export function NotFoundPage({ inApp = false }: { inApp?: boolean }) {
  return (
    <div className={inApp ? '' : 'flex min-h-dvh items-center justify-center'}>
      <EmptyState
        icon={<Compass className="size-6" />}
        title="Page not found"
        body="The page you are looking for does not exist or was moved."
        action={<ButtonLink to={inApp ? '/app' : '/'}>Go back home</ButtonLink>}
      />
    </div>
  );
}
