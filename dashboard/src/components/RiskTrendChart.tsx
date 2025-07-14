'use client'

import {
  Card,
  CardHeader,
  CardBody,
  Heading,
  Box,
  Text,
  Skeleton,
} from '@chakra-ui/react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart,
} from 'recharts'

interface RiskTrendData {
  date: string
  risk_score: number
  vuln_count: number
}

interface RiskTrendChartProps {
  data?: RiskTrendData[]
}

export function RiskTrendChart({ data }: RiskTrendChartProps) {
  // Generate sample data if no real data is available
  const sampleData = [
    { date: '2024-01-01', risk_score: 6.2, vuln_count: 15 },
    { date: '2024-01-02', risk_score: 5.8, vuln_count: 12 },
    { date: '2024-01-03', risk_score: 7.1, vuln_count: 18 },
    { date: '2024-01-04', risk_score: 6.5, vuln_count: 14 },
    { date: '2024-01-05', risk_score: 5.9, vuln_count: 11 },
    { date: '2024-01-06', risk_score: 6.8, vuln_count: 16 },
    { date: '2024-01-07', risk_score: 6.3, vuln_count: 13 },
  ]

  const chartData = data && data.length > 0 ? data : sampleData

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric' 
    })
  }

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <Box
          bg="white"
          p={3}
          border="1px solid"
          borderColor="gray.200"
          borderRadius="md"
          shadow="lg"
        >
          <Text fontSize="sm" fontWeight="bold" mb={1}>
            {formatDate(label)}
          </Text>
          <Text fontSize="sm" color="blue.600">
            Risk Score: {payload[0].value.toFixed(1)}
          </Text>
          <Text fontSize="sm" color="orange.600">
            Vulnerabilities: {payload[1]?.value || 0}
          </Text>
        </Box>
      )
    }
    return null
  }

  return (
    <Card data-testid="chart-container">
      <CardHeader>
        <Heading size="md" color="gray.700">
          📈 Risk Trend (Last 7 Days)
        </Heading>
        <Text fontSize="sm" color="gray.600">
          Risk score and vulnerability count over time
        </Text>
      </CardHeader>
      <CardBody>
        <Box height="300px">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3182CE" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#3182CE" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
              <XAxis 
                dataKey="date" 
                tickFormatter={formatDate}
                stroke="#718096"
                fontSize={12}
              />
              <YAxis 
                yAxisId="risk"
                domain={[0, 10]}
                stroke="#718096"
                fontSize={12}
              />
              <YAxis 
                yAxisId="vuln"
                orientation="right"
                stroke="#718096"
                fontSize={12}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                yAxisId="risk"
                type="monotone"
                dataKey="risk_score"
                stroke="#3182CE"
                strokeWidth={2}
                fill="url(#riskGradient)"
              />
              <Line
                yAxisId="vuln"
                type="monotone"
                dataKey="vuln_count"
                stroke="#ED8936"
                strokeWidth={2}
                dot={{ fill: '#ED8936', strokeWidth: 2, r: 4 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </Box>
      </CardBody>
    </Card>
  )
}