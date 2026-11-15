import { execSync } from 'node:child_process';
import { TEST_DATABASE_URL } from './env';

export default function setup() {
  // Apply the real migrations (including triggers) to the test database.
  execSync('npx prisma migrate deploy', {
    stdio: 'pipe',
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
  });
}
