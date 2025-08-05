"use client"

import { useEffect } from 'react';
import { NetworkTopologyView } from '@/components/simulation-dashboard/NetworkTopologyView';
import { AIServiceMonitor } from '@/components/simulation-dashboard/AIServiceMonitor';
import { ExploitCodeDisplay } from '@/components/simulation-dashboard/ExploitCodeDisplay';
import { SimulationController } from '@/components/simulation-dashboard/SimulationController';
import { RealTimeMetrics } from '@/components/simulation-dashboard/RealTimeMetrics';
import { useWebSocketConnection } from '@/hooks/useWebSocket';
import { useSimulationState, setupSimulationWebSocketHandlers } from '@/hooks/useSimulationState';
import { Activity, Shield } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useRouter } from 'next/navigation'

export default function SimulationPage() {
  const { connected } = useWebSocketConnection();
  const { refreshState, resetSimulationState } = useSimulationState();
  const router = useRouter();
  
  // Setup WebSocket handlers
  useEffect(() => {
    setupSimulationWebSocketHandlers();
  }, []);
  
  // Initial data fetch
  useEffect(() => {
    refreshState();
  }, [refreshState]);

  // Reset simulation state on mount (fresh start)
  useEffect(() => {
    resetSimulationState();
  }, []);
  
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <div className="flex items-center space-x-3">
                <div className="relative">
                  <Shield className="w-8 h-8 text-cyber-500" />
                  <div className={`absolute -top-1 -right-1 w-3 h-3 rounded-full ${connected ? 'bg-status-online animate-pulse' : 'bg-status-offline'}`} />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-foreground">CyberCortex</h1>
                  <p className="text-xs text-muted-foreground">Continuous Self-Penetration Testing System</p>
                </div>
              </div>
              {/* Nav Buttons */}
              <nav className="flex items-center space-x-6 ml-8">
                <Button variant="ghost" size="sm" className="text-white" onClick={() => router.push('/')}> 
                  <Activity className="w-4 h-4 mr-2" />
                  Dashboard
                </Button>
                <Button variant="ghost" size="sm" className="text-cyber-500 bg-background shadow-sm cursor-default">Simulation</Button>
              </nav>
            </div>
            <div className="flex items-center space-x-2">
              <div className="text-sm text-muted-foreground">
                {connected ? (
                  <span className="text-status-online">● Connected</span>
                ) : (
                  <span className="text-status-offline">● Disconnected</span>
                )}
              </div>
            </div>
          </div>
        </div>
      </header>
      
      <main className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column */}
          <div className="lg:col-span-2 space-y-8">
            <NetworkTopologyView />
            <ExploitCodeDisplay />
          </div>
          
          {/* Right Column */}
          <div className="space-y-8">
            <SimulationController />
            <AIServiceMonitor />
            <RealTimeMetrics />
          </div>
        </div>
      </main>
      
      <footer className="border-t py-6">
        <div className="container mx-auto px-4">
          <div className="text-center text-sm text-muted-foreground">
            <p>
              CyberCortex Simulation Environment • All penetration testing activities are performed in an isolated Docker environment
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}