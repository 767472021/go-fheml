package gobrain

import (
	// "testing"
	"fmt"
	"math/rand"

	"github.com/d4l3k/go-fheml/seal"
)

func ExampleSimpleFeedForward() {
	// set the random seed to 0
	rand.Seed(0)

	params := seal.NewEncryptionParamsCKKS()
	c := seal.NewContext(params)
	g := seal.NewKeyGenerator(c)
	pub := g.PublicKey()
	sec := g.SecretKey()
	relin := g.RelinKeys(60, 2)

	encr := seal.NewEncryptor(c, pub)
	enco := seal.NewCKKSEncoder(c)
	decr := seal.NewDecryptor(c, sec)

	e := func(a float64) *seal.Ciphertext {
		return encr.Encrypt(enco.Encode(a))
	}

	d := func(in []*seal.Ciphertext) []float64 {
		var out []float64
		for _, cipher := range in {
			out = append(out, enco.Decode(decr.Decrypt(cipher)))
		}
		return out
	}

	// create the XOR representation patter to train the network
	patterns := [][][]*seal.Ciphertext{
		{{e(0), e(0)}, {e(0)}},
		{{e(0), e(1)}, {e(1)}},
		{{e(1), e(0)}, {e(1)}},
		{{e(1), e(1)}, {e(0)}},
	}

	// instantiate the Feed Forward
	ff := &FeedForward{
		Encryptor: encr,
		Evaluator: seal.NewEvaluator(c),
		Encoder:   enco,
		RelinKeys: relin,
	}

	// initialize the Neural Network;
	// the networks structure will contain:
	// 2 inputs, 2 hidden nodes and 1 output.
	ff.Init(2, 2, 1)

	// train the network using the XOR patterns
	// the training will run for 1000 epochs
	// the learning rate is set to 0.6 and the momentum factor to 0.4
	// use true in the last parameter to receive reports about the learning error
	fmt.Println("Train", d(ff.Train(patterns, 1, 0.6, 0.4)))

	// testing the network
	//ff.Test(patterns)

	// predicting a value
	inputs := []*seal.Ciphertext{e(1), e(1)}
	fmt.Println("Predict", d(ff.Update(inputs)))

	// Output:
	// [0 0] -> [0.05750394570844524]  :  [0]
	// [0 1] -> [0.9301006350712102]  :  [1]
	// [1 0] -> [0.927809966227284]  :  [1]
	// [1 1] -> [0.09740879532462095]  :  [0]
}
