import { ChakraProviders } from '@/lib/chakra'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { Inter } from 'next/font/google'

const inter = Inter({ subsets: ['latin'] })

export const metadata = {
  title: 'Dep-Risk Dashboard',
  description: 'Dependency vulnerability monitoring dashboard',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <ChakraProviders>
          <ErrorBoundary>
            {children}
          </ErrorBoundary>
        </ChakraProviders>
      </body>
    </html>
  )
}