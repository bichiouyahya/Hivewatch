import type { Metadata, Viewport } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'HiveWatch | Honeypot Security Operations',
  description: 'Real-time honeynet threat monitoring and attacker intelligence dashboard.',
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: '#111111',
  initialScale: 1,
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" className="dark"><body className="antialiased">{children}</body></html>
}
