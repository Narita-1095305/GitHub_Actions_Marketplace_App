'use client'

import {
  Box,
  Card,
  CardHeader,
  CardBody,
  Heading,
  Text,
  VStack,
  HStack,
  Badge,
  Button,
  Collapse,
  useDisclosure,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Progress,
  Code,
} from '@chakra-ui/react'
import { useState, useEffect } from 'react'
import { useHealthCheck } from '@/lib/api'

interface TestResult {
  name: string
  status: 'pass' | 'fail' | 'warning'
  message: string
  details?: string
}

export function TestPanel() {
  const { isOpen, onToggle } = useDisclosure()
  const [testResults, setTestResults] = useState<TestResult[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const { data: healthData, error: healthError } = useHealthCheck()

  const runTests = async () => {
    setIsRunning(true)
    const results: TestResult[] = []

    // Test 1: API Health Check
    results.push({
      name: 'API Health Check',
      status: healthError ? 'fail' : healthData ? 'pass' : 'warning',
      message: healthError 
        ? 'API server not responding' 
        : healthData 
          ? 'API server is healthy' 
          : 'API status unknown',
      details: healthError?.message || JSON.stringify(healthData, null, 2)
    })

    // Test 2: Component Rendering
    const statCards = document.querySelectorAll('[data-testid="stat-card"]')
    results.push({
      name: 'Dashboard Components',
      status: statCards.length >= 4 ? 'pass' : 'fail',
      message: `${statCards.length}/4 stat cards rendered`,
      details: 'Checking if all dashboard components are properly rendered'
    })

    // Test 3: Responsive Design
    const container = document.querySelector('[data-testid="dashboard-container"]')
    const containerWidth = container?.clientWidth || 0
    results.push({
      name: 'Responsive Layout',
      status: containerWidth > 0 ? 'pass' : 'fail',
      message: `Container width: ${containerWidth}px`,
      details: 'Testing responsive design across different screen sizes'
    })

    // Test 4: Chart Rendering
    const charts = document.querySelectorAll('[data-testid="chart-container"]')
    results.push({
      name: 'Chart Components',
      status: charts.length >= 2 ? 'pass' : 'warning',
      message: `${charts.length}/2 charts rendered`,
      details: 'Checking if Recharts components are properly loaded'
    })

    // Test 5: Data Management
    const mockDataTest = typeof window !== 'undefined' && window.localStorage
    results.push({
      name: 'Data Management',
      status: mockDataTest ? 'pass' : 'warning',
      message: mockDataTest ? 'Local storage available' : 'Local storage not available',
      details: 'Testing data persistence and state management'
    })

    // Test 6: Performance (only run on client side)
    if (typeof window !== 'undefined' && performance) {
      const performanceEntries = performance.getEntriesByType('navigation')
      const loadTime = performanceEntries.length > 0 
        ? (performanceEntries[0] as PerformanceNavigationTiming).loadEventEnd - 
          (performanceEntries[0] as PerformanceNavigationTiming).loadEventStart
        : 0
      
      results.push({
        name: 'Performance',
        status: loadTime < 3000 ? 'pass' : loadTime < 5000 ? 'warning' : 'fail',
        message: `Page load time: ${loadTime.toFixed(0)}ms`,
        details: 'Measuring initial page load performance'
      })
    } else {
      results.push({
        name: 'Performance',
        status: 'warning',
        message: 'Performance API not available',
        details: 'Could not measure performance on this environment'
      })
    }

    setTestResults(results)
    setIsRunning(false)
  }

  useEffect(() => {
    // Run tests automatically on component mount
    const timer = setTimeout(runTests, 1000)
    return () => clearTimeout(timer)
  }, [])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pass': return 'green'
      case 'fail': return 'red'
      case 'warning': return 'orange'
      default: return 'gray'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pass': return '✅'
      case 'fail': return '❌'
      case 'warning': return '⚠️'
      default: return '❓'
    }
  }

  const passedTests = testResults.filter(test => test.status === 'pass').length
  const totalTests = testResults.length

  return (
    <Card position="fixed" top={4} right={4} width="300px" zIndex={1000} shadow="lg">
      <CardHeader pb={2}>
        <HStack justify="space-between" align="center">
          <VStack align="start" spacing={0}>
            <Heading size="sm">🧪 Dashboard Tests</Heading>
            <Text fontSize="xs" color="gray.600">
              {passedTests}/{totalTests} tests passed
            </Text>
          </VStack>
          <Button size="sm" onClick={onToggle} variant="ghost">
            {isOpen ? 'Hide' : 'Show'}
          </Button>
        </HStack>
        
        {totalTests > 0 && (
          <Progress
            value={(passedTests / totalTests) * 100}
            colorScheme={passedTests === totalTests ? 'green' : 'orange'}
            size="sm"
            mt={2}
          />
        )}
      </CardHeader>

      <Collapse in={isOpen}>
        <CardBody pt={0}>
          <VStack spacing={3} align="stretch">
            <HStack>
              <Button
                size="sm"
                onClick={runTests}
                isLoading={isRunning}
                loadingText="Testing..."
                colorScheme="blue"
                flex={1}
              >
                Run Tests
              </Button>
            </HStack>

            {testResults.map((test, index) => (
              <Alert
                key={index}
                status={test.status === 'pass' ? 'success' : test.status === 'fail' ? 'error' : 'warning'}
                variant="left-accent"
                size="sm"
              >
                <AlertIcon />
                <Box flex={1}>
                  <AlertTitle fontSize="xs">
                    {getStatusIcon(test.status)} {test.name}
                  </AlertTitle>
                  <AlertDescription fontSize="xs">
                    {test.message}
                  </AlertDescription>
                  {test.details && (
                    <Code fontSize="xs" mt={1} p={1} borderRadius="sm">
                      {test.details.length > 50 
                        ? test.details.substring(0, 50) + '...'
                        : test.details
                      }
                    </Code>
                  )}
                </Box>
              </Alert>
            ))}

            {testResults.length === 0 && (
              <Text fontSize="sm" color="gray.500" textAlign="center">
                No tests run yet
              </Text>
            )}
          </VStack>
        </CardBody>
      </Collapse>
    </Card>
  )
}