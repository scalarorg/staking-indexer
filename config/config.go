package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/joho/godotenv"
	// "github.com/babylonchain/staking-indexer/utils"
)

const (
	defaultLogLevel       = "info"
	defaultLogDirname     = "logs"
	defaultLogFilename    = "sid.log"
	defaultConfigFileName = "sid.conf"
	defaultParamsFileName = "global-params.json"
	defaultBitcoinNetwork = "signet"
	defaultDataDirname    = "data"
)

var (
	//   C:\Users\<username>\AppData\Local\ on Windows
	//   ~/.fpd on Linux
	//   ~/Users/<username>/Library/Application Support/Sid on MacOS
	DefaultHomeDir    = btcutil.AppDataDir("sid", false)
	DefaultParamsPath = ParamsFile(DefaultHomeDir)
)

type Config struct {
	LogLevel       string         `long:"loglevel" description:"Logging level for all subsystems" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal"`
	BitcoinNetwork string         `long:"bitcoinnetwork" description:"Bitcoin network to run on" choice:"mainnet" choice:"regtest" choice:"testnet" choice:"simnet" choice:"signet"`
	BTCConfig      *BTCConfig     `group:"btcconfig" namespace:"btcconfig"`
	DatabaseConfig *DBConfig      `group:"dbconfig" namespace:"dbconfig"`
	QueueConfig    *QueueConfig   `group:"queueconfig" namespace:"queueconfig"`
	MetricsConfig  *MetricsConfig `group:"metricsconfig" namespace:"metricsconfig"`

	BTCNetParams chaincfg.Params
}

func DefaultConfigWithHome(homePath string) *Config {
	cfg := &Config{
		LogLevel:       defaultLogLevel,
		BitcoinNetwork: defaultBitcoinNetwork,
		BTCConfig:      DefaultBTCConfig(),
		DatabaseConfig: DefaultDBConfigWithHomePath(homePath),
		QueueConfig:    DefaultQueueConfig(),
		MetricsConfig:  DefaultMetricsConfig(),
	}

	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	return cfg
}

func DefaultConfig() *Config {
	return DefaultConfigWithHome(DefaultHomeDir)
}

func ConfigFile(homePath string) string {
	return filepath.Join(homePath, defaultConfigFileName)
}

func ParamsFile(homePath string) string {
	return filepath.Join(homePath, defaultParamsFileName)
}

func LogDir(homePath string) string {
	return filepath.Join(homePath, defaultLogDirname)
}

func LogFile(homePath string) string {
	return filepath.Join(LogDir(homePath), defaultLogFilename)
}

func DataDir(homePath string) string {
	return filepath.Join(homePath, defaultDataDirname)
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("[WARN] No .env file found, just alert for development")
	}

	var cfg Config

	cfg.LogLevel = os.Getenv("LOG_LEVEL")
	cfg.BitcoinNetwork = os.Getenv("BITCOIN_NETWORK")

	maxPeer, err := strconv.Atoi(os.Getenv("PRUNED_NODE_MAX_PEERS"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse pruned node max peers: %w", err)
	}

	blockInterval := os.Getenv("BLOCK_POLLING_INTERVAL")
	blockIntervalDuration, err := time.ParseDuration(blockInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block polling interval: %w", err)
	}
	txPollingInterval := os.Getenv("TX_POLLING_INTERVAL")
	txPollingIntervalDuration, err := time.ParseDuration(txPollingInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tx polling interval: %w", err)
	}

	cacheSize := os.Getenv("BLOCK_CACHE_SIZE")
	cacheSizeUint64, err := strconv.ParseUint(cacheSize, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block cache size: %w", err)
	}

	maxRetryTimes, err := strconv.Atoi(os.Getenv("MAX_RETRY_TIMES"))
	if err != nil {
		return nil, err
	}

	retryInterval, err := time.ParseDuration(os.Getenv("RETRY_INTERVAL"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse retry interval: %w", err)
	}

	cfg.BTCConfig = &BTCConfig{
		RPCHost:              os.Getenv("BITCOIN_NODE_ADDRESS"),
		RPCUser:              os.Getenv("BITCOIN_USER"),
		RPCPass:              os.Getenv("BITCOIN_PASSWORD"),
		PrunedNodeMaxPeers:   maxPeer,
		BlockPollingInterval: blockIntervalDuration,
		TxPollingInterval:    txPollingIntervalDuration,
		BlockCacheSize:       cacheSizeUint64,
		MaxRetryTimes:        uint(maxRetryTimes),
		RetryInterval:        retryInterval,
	}

	autoCompactMinAge, err := time.ParseDuration(os.Getenv("AUTO_COMPACT_MIN_AGE"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse auto compact min age: %w", err)
	}

	timeOut, err := time.ParseDuration(os.Getenv("DB_TIMEOUT"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse db timeout: %w", err)
	}

	cfg.DatabaseConfig = &DBConfig{
		DBPath:            os.Getenv("DB_PATH"),
		DBFileName:        os.Getenv("DB_FILE_NAME"),
		NoFreelistSync:    os.Getenv("NO_FREELIST_SYNC") == "true",
		AutoCompact:       os.Getenv("AUTO_COMPACT") == "true",
		AutoCompactMinAge: autoCompactMinAge,
		DBTimeout:         timeOut,
	}

	processinTimeout, err := time.ParseDuration(os.Getenv("PROCESSING_TIMEOUT"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse processing timeout: %w", err)
	}

	msgMaxRetryAttempts, err := strconv.Atoi(os.Getenv("MSG_MAX_RETRY_ATTEMPTS"))
	if err != nil {
		return nil, err
	}

	reQueueDelayTime, err := time.ParseDuration(os.Getenv("REQUEUE_DELAY_TIME"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse requeue delay time: %w", err)
	}

	cfg.QueueConfig = &QueueConfig{
		User:                os.Getenv("RABBITMQ_USER"),
		Password:            os.Getenv("RABBITMQ_PASSWORD"),
		Url:                 os.Getenv("RAIBBITMQ_URL"),
		ProcessingTimeout:   processinTimeout,
		MsgMaxRetryAttempts: int32(msgMaxRetryAttempts),
		ReQueueDelayTime:    reQueueDelayTime,
		QueueType:           os.Getenv("QUEUE_TYPE"),
	}

	cfg.MetricsConfig = &MetricsConfig{
		Url: os.Getenv("METRICS_URL"),
	}

	// Make sure everything we just loaded makes sense.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate checks the given configuration to be sane. This makes sure no
// illegal values or combination of values are set. All file system paths are
// normalized. The cleaned up config is returned on success.
func (cfg *Config) Validate() error {
	// Multiple networks can't be selected simultaneously.  Count number of
	// network flags passed; assign active network params
	// while we're at it.
	fmt.Printf("Bitcoin network %s\n", cfg.BitcoinNetwork)
	switch cfg.BitcoinNetwork {
	case "mainnet":
		cfg.BTCNetParams = chaincfg.MainNetParams
	case "testnet4":
		cfg.BTCNetParams = TestNet4Params
	case "testnet3":
		cfg.BTCNetParams = chaincfg.TestNet3Params
	case "regtest":
		cfg.BTCNetParams = chaincfg.RegressionNetParams
	case "simnet":
		cfg.BTCNetParams = chaincfg.SimNetParams
	case "signet":
		cfg.BTCNetParams = chaincfg.SigNetParams
	default:
		return fmt.Errorf("invalid network: %v", cfg.BitcoinNetwork)
	}

	if err := cfg.DatabaseConfig.Validate(); err != nil {
		return err
	}

	if err := cfg.MetricsConfig.Validate(); err != nil {
		return err
	}

	if err := cfg.QueueConfig.Validate(); err != nil {
		return err
	}

	if err := cfg.BTCConfig.Validate(); err != nil {
		return err
	}

	// All good, return the sanitized result.
	return nil
}
