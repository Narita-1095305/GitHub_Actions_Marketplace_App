'use client'

import {
  SimpleGrid,
  Card,
  CardBody,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  StatArrow,
  Badge,
  HStack,
  Icon,
  Skeleton,
  Box,
} from '@chakra-ui/react'
import { WarningIcon, CheckCircleIcon, InfoIcon, TimeIcon } from '@chakra-ui/icons'
import { DashboardData } from '@/lib/api'
import { useState, useEffect } from 'react'

interface DashboardStatsProps {
  data?: DashboardData
  isLoading: boolean
}

export function DashboardStats({ data, isLoading }: DashboardStatsProps) {
  const [isClient, setIsClient] = useState(false)
  
  useEffect(() => {
    setIsClient(true)
  }, [])

  if (isLoading) {
    return (
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6}>
        {[...Array(4)].map((_, i) => (
          <Card key={i} data-testid="stat-card">
            <CardBody>
              <Skeleton height="80px" />
            </CardBody>
          </Card>
        ))}
      </SimpleGrid>
    )
  }

  const summary = data?.summary

  const getRiskColor = (score: number) => {
    if (score >= 7) return 'red'
    if (score >= 4) return 'orange'
    return 'green'
  }

  const getRiskIcon = (score: number) => {
    if (score >= 7) return WarningIcon
    if (score >= 4) return InfoIcon
    return CheckCircleIcon
  }

  return (
    <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6}>
      {/* Average Risk Score */}
      <Card data-testid="stat-card">
        <CardBody>
          <Stat>
            <HStack justify="space-between" align="start">
              <Box>
                <StatLabel fontSize="sm" color="gray.600">
                  Average Risk Score
                </StatLabel>
                <StatNumber 
                  fontSize="2xl" 
                  color={`${getRiskColor(summary?.average_risk_score || 0)}.500`}
                >
                  {summary?.average_risk_score?.toFixed(1) || '0.0'}
                </StatNumber>
              </Box>
              <Icon 
                as={getRiskIcon(summary?.average_risk_score || 0)} 
                boxSize={6} 
                color={`${getRiskColor(summary?.average_risk_score || 0)}.500`}
              />
            </HStack>
            <StatHelpText>
              <Badge 
                colorScheme={getRiskColor(summary?.average_risk_score || 0)} 
                variant="subtle"
              >
                {summary?.average_risk_score && summary.average_risk_score >= 7 ? 'High Risk' : 
                 summary?.average_risk_score && summary.average_risk_score >= 4 ? 'Medium Risk' : 'Low Risk'}
              </Badge>
            </StatHelpText>
          </Stat>
        </CardBody>
      </Card>

      {/* Total Repositories */}
      <Card data-testid="stat-card">
        <CardBody>
          <Stat>
            <HStack justify="space-between" align="start">
              <Box>
                <StatLabel fontSize="sm" color="gray.600">
                  Total Repositories
                </StatLabel>
                <StatNumber fontSize="2xl" color="blue.500">
                  {summary?.total_repositories || 0}
                </StatNumber>
              </Box>
              <Icon as={InfoIcon} boxSize={6} color="blue.500" />
            </HStack>
            <StatHelpText>
              <Badge colorScheme="blue" variant="subtle">
                {summary?.high_risk_repos || 0} high risk
              </Badge>
            </StatHelpText>
          </Stat>
        </CardBody>
      </Card>

      {/* Total Vulnerabilities */}
      <Card data-testid="stat-card">
        <CardBody>
          <Stat>
            <HStack justify="space-between" align="start">
              <Box>
                <StatLabel fontSize="sm" color="gray.600">
                  Total Vulnerabilities
                </StatLabel>
                <StatNumber fontSize="2xl" color="orange.500">
                  {summary?.total_vulnerabilities || 0}
                </StatNumber>
              </Box>
              <Icon as={WarningIcon} boxSize={6} color="orange.500" />
            </HStack>
            <StatHelpText>
              Across {summary?.total_scans || 0} scans
            </StatHelpText>
          </Stat>
        </CardBody>
      </Card>

      {/* Last Scan */}
      <Card data-testid="stat-card">
        <CardBody>
          <Stat>
            <HStack justify="space-between" align="start">
              <Box>
                <StatLabel fontSize="sm" color="gray.600">
                  Last Scan
                </StatLabel>
                <StatNumber fontSize="lg" color="gray.700">
                  {isClient && summary?.last_scan_time 
                    ? new Date(summary.last_scan_time).toLocaleDateString()
                    : !isClient ? 'Loading...' : 'Never'
                  }
                </StatNumber>
              </Box>
              <Icon as={TimeIcon} boxSize={6} color="gray.500" />
            </HStack>
            <StatHelpText>
              <Badge 
                colorScheme={summary?.last_scan_time ? 'green' : 'gray'} 
                variant="subtle"
              >
                {summary?.last_scan_time ? 'Active' : 'No scans'}
              </Badge>
            </StatHelpText>
          </Stat>
        </CardBody>
      </Card>
    </SimpleGrid>
  )
}