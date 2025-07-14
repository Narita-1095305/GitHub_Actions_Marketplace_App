'use client'

import {
  Card,
  CardHeader,
  CardBody,
  Heading,
  Text,
  SimpleGrid,
  Box,
  Badge,
  VStack,
  HStack,
  Progress,
  Tooltip,
  Icon,
} from '@chakra-ui/react'
import { ArrowUpIcon, ArrowDownIcon, MinusIcon } from '@chakra-ui/icons'
import { useState, useEffect } from 'react'

interface RepositoryStats {
  repository: {
    id: number
    name: string
    language: string
  }
  latest_scan: {
    overall_risk_score: number
    total_vulnerabilities: number
  }
  risk_trend: 'increasing' | 'decreasing' | 'stable'
  last_scan_time: string
}

interface RepositoryHeatmapProps {
  data?: RepositoryStats[]
}

export function RepositoryHeatmap({ data }: RepositoryHeatmapProps) {
  const [isClient, setIsClient] = useState(false)
  
  useEffect(() => {
    setIsClient(true)
  }, [])

  // Sample data if no real data is available
  const sampleData: RepositoryStats[] = [
    {
      repository: { id: 1, name: 'frontend-app', language: 'TypeScript' },
      latest_scan: { overall_risk_score: 8.2, total_vulnerabilities: 15 },
      risk_trend: 'increasing',
      last_scan_time: '2024-01-07T10:30:00Z',
    },
    {
      repository: { id: 2, name: 'api-server', language: 'Go' },
      latest_scan: { overall_risk_score: 3.5, total_vulnerabilities: 3 },
      risk_trend: 'decreasing',
      last_scan_time: '2024-01-07T09:15:00Z',
    },
    {
      repository: { id: 3, name: 'data-processor', language: 'Python' },
      latest_scan: { overall_risk_score: 6.8, total_vulnerabilities: 12 },
      risk_trend: 'stable',
      last_scan_time: '2024-01-07T08:45:00Z',
    },
    {
      repository: { id: 4, name: 'mobile-app', language: 'React Native' },
      latest_scan: { overall_risk_score: 5.2, total_vulnerabilities: 7 },
      risk_trend: 'decreasing',
      last_scan_time: '2024-01-06T16:20:00Z',
    },
    {
      repository: { id: 5, name: 'auth-service', language: 'Java' },
      latest_scan: { overall_risk_score: 4.1, total_vulnerabilities: 5 },
      risk_trend: 'stable',
      last_scan_time: '2024-01-06T14:10:00Z',
    },
    {
      repository: { id: 6, name: 'notification-worker', language: 'Node.js' },
      latest_scan: { overall_risk_score: 7.3, total_vulnerabilities: 18 },
      risk_trend: 'increasing',
      last_scan_time: '2024-01-06T12:30:00Z',
    },
  ]

  const repositories = data && data.length > 0 ? data : sampleData

  const getRiskColor = (score: number) => {
    if (score >= 7) return 'red'
    if (score >= 4) return 'orange'
    return 'green'
  }

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'increasing': return ArrowUpIcon
      case 'decreasing': return ArrowDownIcon
      default: return MinusIcon
    }
  }

  const getTrendColor = (trend: string) => {
    switch (trend) {
      case 'increasing': return 'red'
      case 'decreasing': return 'green'
      default: return 'gray'
    }
  }

  const getLanguageColor = (language: string) => {
    const colors: Record<string, string> = {
      'TypeScript': 'blue',
      'JavaScript': 'yellow',
      'Go': 'cyan',
      'Python': 'green',
      'Java': 'orange',
      'Node.js': 'green',
      'React Native': 'purple',
    }
    return colors[language] || 'gray'
  }

  const formatTimeAgo = (dateStr: string) => {
    if (!isClient) return 'Loading...'
    
    const date = new Date(dateStr)
    const now = new Date()
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60))
    
    if (diffInHours < 1) return 'Just now'
    if (diffInHours < 24) return `${diffInHours}h ago`
    const diffInDays = Math.floor(diffInHours / 24)
    return `${diffInDays}d ago`
  }

  return (
    <Card>
      <CardHeader>
        <Heading size="md" color="gray.700">
          🗺️ Repository Risk Heatmap
        </Heading>
        <Text fontSize="sm" color="gray.600">
          Risk scores and trends across {repositories.length} repositories
        </Text>
      </CardHeader>
      
      <CardBody>
        <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={4}>
          {repositories.map((repo) => (
            <Tooltip
              key={repo.repository.id}
              label={`${repo.latest_scan.total_vulnerabilities} vulnerabilities • Last scan: ${formatTimeAgo(repo.last_scan_time)}`}
              placement="top"
            >
              <Box
                p={4}
                borderRadius="lg"
                border="1px solid"
                borderColor="gray.200"
                bg="white"
                _hover={{ 
                  shadow: 'md', 
                  borderColor: 'gray.300',
                  transform: 'translateY(-2px)',
                  transition: 'all 0.2s'
                }}
                cursor="pointer"
              >
                <VStack spacing={3} align="stretch">
                  {/* Header */}
                  <HStack justify="space-between">
                    <VStack align="start" spacing={1}>
                      <Text fontSize="sm" fontWeight="semibold" color="gray.800">
                        {repo.repository.name}
                      </Text>
                      <Badge
                        colorScheme={getLanguageColor(repo.repository.language)}
                        variant="subtle"
                        fontSize="xs"
                      >
                        {repo.repository.language}
                      </Badge>
                    </VStack>
                    <HStack spacing={1}>
                      <Icon
                        as={getTrendIcon(repo.risk_trend)}
                        color={`${getTrendColor(repo.risk_trend)}.500`}
                        boxSize={3}
                      />
                      <Text fontSize="xs" color={`${getTrendColor(repo.risk_trend)}.500`}>
                        {repo.risk_trend}
                      </Text>
                    </HStack>
                  </HStack>

                  {/* Risk Score */}
                  <Box>
                    <HStack justify="space-between" mb={1}>
                      <Text fontSize="xs" color="gray.600">
                        Risk Level
                      </Text>
                      <Text fontSize="xs" color="gray.600">
                        {repo.latest_scan.overall_risk_score.toFixed(1)}/10
                      </Text>
                    </HStack>
                    <Progress
                      value={(repo.latest_scan.overall_risk_score / 10) * 100}
                      colorScheme={getRiskColor(repo.latest_scan.overall_risk_score)}
                      size="sm"
                      borderRadius="full"
                    />
                  </Box>

                  {/* Footer */}
                  <HStack justify="space-between" align="center">
                    <Text fontSize="xs" color="gray.500">
                      {repo.latest_scan.total_vulnerabilities} vulns
                    </Text>
                    <Text fontSize="xs" color="gray.500">
                      {formatTimeAgo(repo.last_scan_time)}
                    </Text>
                  </HStack>
                </VStack>
              </Box>
            </Tooltip>
          ))}
        </SimpleGrid>
      </CardBody>
    </Card>
  )
}