'use client'

import React, { Component, ReactNode } from 'react'
import {
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Box,
  Button,
  VStack,
  Text,
} from '@chakra-ui/react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error?: Error
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    if (process.env.NODE_ENV === 'development') {
      console.error('ErrorBoundary caught an error:', error, errorInfo)
    }
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback
      }

      return (
        <Box p={6}>
          <Alert status="error" borderRadius="md">
            <AlertIcon />
            <VStack align="start" spacing={3}>
              <AlertTitle>Something went wrong!</AlertTitle>
              <AlertDescription>
                <Text fontSize="sm">
                  We encountered an unexpected error. Please try refreshing the page.
                </Text>
                {process.env.NODE_ENV === 'development' && this.state.error && (
                  <Text fontSize="xs" mt={2} color="gray.600">
                    {this.state.error.message}
                  </Text>
                )}
              </AlertDescription>
              <Button
                size="sm"
                colorScheme="red"
                variant="outline"
                onClick={() => window.location.reload()}
              >
                Refresh Page
              </Button>
            </VStack>
          </Alert>
        </Box>
      )
    }

    return this.props.children
  }
}