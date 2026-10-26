import React from 'react';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { Landing } from './pages/Landing';
import { Scope } from './pages/Scope';
import { Intel } from './pages/Intel';
import { PcapAnalyzer } from './pages/PcapAnalyzer';
import { Alerts } from './pages/Alerts';
import { Stats } from './pages/Stats';
import { useStream } from './hooks/useStream';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5000,
      refetchOnWindowFocus: false,
    },
  },
});

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();
  const stream = useStream();
  const isLanding = location.pathname === '/';

  if (isLanding) {
    return <>{children}</>;
  }

  return (
    <div className="min-h-screen flex flex-col bg-[#050506] text-[#f2f0e9]">
      <Header
        connected={stream.connected}
        flowCount={stream.flowCount}
        isDemo={stream.isDemo}
      />
      <main className="flex-1 flex flex-col">{children}</main>
      <Footer />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/scope" element={<Scope />} />
            <Route path="/intel" element={<Intel />} />
            <Route path="/pcap" element={<PcapAnalyzer />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/stats" element={<Stats />} />
            <Route path="*" element={<Landing />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </QueryClientProvider>
  );
};
