'use client'

import {
  Box,
  Container,
  Heading,
  Text,
  SimpleGrid,
  Card,
  CardBody,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  StatArrow,
  Badge,
  VStack,
  HStack,
  Button,
  Select,
  Input,
  InputGroup,
  InputLeftElement,
  Icon,
} from '@chakra-ui/react'
import { SearchIcon, WarningIcon, CheckCircleIcon, InfoIcon } from '@chakra-ui/icons'
import { useState, useEffect } from 'react'
import dynamic from 'next/dynamic'
import { DashboardStats } from '@/components/DashboardStats'
import { useDashboardData, useHealthCheck } from '@/lib/api'
import { TestPanel } from '@/components/TestPanel'

const RiskTrendChart = dynamic(() => import('@/components/RiskTrendChart').then(mod => mod.RiskTrendChart), { ssr: false, loading: () => <p>Loading chart...</p> })
const RepositoryHeatmap = dynamic(() => import('@/components/RepositoryHeatmap').then(mod => mod.RepositoryHeatmap), { ssr: false, loading: () => <p>Loading heatmap...</p> })
const VulnerabilityTable = dynamic(() => import('@/components/VulnerabilityTable').then(mod => mod.VulnerabilityTable), { ssr: false, loading: () => <p>Loading table...</p> })

export default function Dashboard() {
  const [selectedOrg, setSelectedOrg] = useState('example-org')
  const [searchTerm, setSearchTerm] = useState('')
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)
  const [isClient, setIsClient] = useState(false)
  
  const { data: dashboardData, error, isLoading, refreshData, isConnected } = useDashboardData(selectedOrg)
  const { data: healthData, error: healthError } = useHealthCheck()
  
  // Ensure we're running on the client side
  useEffect(() => {
    setIsClient(true)
    setLastUpdate(new Date())
  }, [])
  
  // Update last refresh time when data changes
  useEffect(() => {
    if (dashboardData && isClient) {
      setLastUpdate(new Date())
    }
  }, [dashboardData, isClient])
  
  const handleManualRefresh = () => {
    refreshData()
    if (isClient) {
      setLastUpdate(new Date())
    }
  }

  return (
    <Box minH="100vh" bg="gray.50" data-testid="dashboard-container">
      {/* Test Panel */}
      <TestPanel />
      
      {/* Header */}
      <Box bg="white" shadow="sm" borderBottom="1px" borderColor="gray.200">
        <Container maxW="7xl" py={4}>
          <HStack justify="space-between" align="center">
            <VStack align="start" spacing={1}>
              <Heading size="lg" color="gray.800">
                🛡️ Dep-Risk Dashboard
              </Heading>
              <Text color="gray.600" fontSize="sm">
                Dependency vulnerability monitoring for {selectedOrg}
              </Text>
            </VStack>
            
            <HStack spacing={4}>
              {/* API Connection Status */}
              <HStack spacing={2}>
                <Box
                  w={3}
                  h={3}
                  borderRadius="full"
                  bg={isConnected ? 'green.400' : 'red.400'}
                  boxShadow={isConnected ? '0 0 8px rgba(72, 187, 120, 0.6)' : '0 0 8px rgba(245, 101, 101, 0.6)'}
                />
                <Text fontSize="xs" color="gray.600">
                  {isConnected ? 'API Connected' : 'Using Mock Data'}
                </Text>
              </HStack>
              
              <Select
                value={selectedOrg}
                onChange={(e) => setSelectedOrg(e.target.value)}
                width="200px"
                bg="white"
              >
                <option value="example-org">Example Org</option>
                <option value="test-org">Test Org</option>
              </Select>
              
              <InputGroup width="300px">
                <InputLeftElement>
                  <SearchIcon color="gray.400" />
                </InputLeftElement>
                <Input
                  placeholder="Search repositories..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  bg="white"
                />
              </InputGroup>
              
              <Button 
                colorScheme="blue" 
                size="sm" 
                onClick={handleManualRefresh}
                isLoading={isLoading}
                loadingText="Refreshing"
              >
                🔄 Refresh
              </Button>
              
              <Button colorScheme="brand" size="sm">
                Export Report
              </Button>
            </HStack>
          </HStack>
        </Container>
      </Box>

      {/* Main Content */}
      <Container maxW="7xl" py={8}>
        <VStack spacing={8} align="stretch">
          {/* Stats Overview */}
          <DashboardStats data={dashboardData} isLoading={isLoading} />
          
          {/* Charts Row */}
          <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6}>
            <RiskTrendChart data={dashboardData?.risk_trend} />
            <RepositoryHeatmap data={dashboardData?.repository_stats} />
          </SimpleGrid>
          
          {/* Vulnerability Table */}
          <VulnerabilityTable 
            data={dashboardData?.top_vulnerabilities} 
            searchTerm={searchTerm}
          />
          
          {/* Real-time Status Bar */}
          <Card>
            <CardBody py={3}>
              <HStack justify="space-between" align="center">
                <HStack spacing={4}>
                  <Text fontSize="sm" color="gray.600">
                    📊 Dashboard Status
                  </Text>
                  <Badge 
                    colorScheme={isConnected ? 'green' : 'orange'} 
                    variant="subtle"
                  >
                    {isConnected ? 'Live Data' : 'Mock Data'}
                  </Badge>
                  <Text fontSize="xs" color="gray.500">
                    Last updated: {isClient && lastUpdate ? lastUpdate.toLocaleTimeString() : 'Loading...'}
                  </Text>
                </HStack>
                
                <HStack spacing={3}>
                  <Text fontSize="xs" color="gray.500">
                    Auto-refresh: 15s
                  </Text>
                  {isLoading && (
                    <HStack spacing={1}>
                      <Box
                        w={2}
                        h={2}
                        borderRadius="full"
                        bg="blue.400"
                        animation="pulse 1s infinite"
                      />
                      <Text fontSize="xs" color="blue.600">
                        Updating...
                      </Text>
                    </HStack>
                  )}
                  <Text fontSize="xs" color="gray.500">
                    API: {healthError ? '❌ Offline' : '✅ Online'}
                  </Text>
                </HStack>
              </HStack>
            </CardBody>
          </Card>
        </VStack>
      </Container>
    </Box>
  )
}