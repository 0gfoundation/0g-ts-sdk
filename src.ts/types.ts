export type RetryOpts = {
    Retries: number
    Interval: number
    MaxGasPrice: number
    TooManyDataRetries?: number // for "too many data writing" errors
}

export type Hash = string

export type Base64 = string
