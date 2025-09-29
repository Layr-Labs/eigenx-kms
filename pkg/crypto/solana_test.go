package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateWalletFromMnemonicSeed(t *testing.T) {
	t.Run("test generate solana wallet from mnemonic seed", func(t *testing.T) {
		// copied from generated addresses from https://solana.com/developers/cookbook/wallets/restore-from-mnemonic
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		expectedPublicKeys := []string{
			"HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
			"Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb",
			"7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm",
			"3YqEpfo3c818GhvbQ1UmVY1nJxw16vtu4JB9peJXT94k",
			"6nod592sTfEWD3VSVPdQndLMVBCNmMc6ngt7MyGBK21j",
			"2EUrWmf5xMmWER9BtDbXbGbZjoL7R3eTDMXYR6H6cKPj",
			"5P2eQoLncuFMjAmNNF4PspnAXYNaDSE2t1gb5os76Svw",
			"9h1cLBiraaUqM1CdJTaVaew1oQtgQUW24FZ8YdnLLgJY",
			"GS6Y8rQB8W3SWfLpQuooT1pEm7mqRKnTP1EkNKL2Xeha",
			"HDyTY5B1TJ3WgyfaziZtDGaBqj3ofKm8499Q8meqk4nx",
		}

		for i := uint32(0); i < 10; i++ {
			wallet, err := GenerateSolanaWalletFromMnemonicSeed(mnemonic, i)
			require.NoError(t, err)
			require.Equal(t, expectedPublicKeys[i], wallet.PublicKey().String())
		}
	})
}
