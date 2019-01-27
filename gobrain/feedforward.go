// Package gobrain provides basic neural networks algorithms.
package gobrain

import (
	"fmt"
	"log"

	"github.com/d4l3k/go-fheml/seal"
)

// FeedForwad struct is used to represent a simple neural network
type FeedForward struct {
	Encryptor *seal.Encryptor
	Evaluator *seal.Evaluator
	Encoder   *seal.CKKSEncoder
	RelinKeys *seal.RelinKeys

	// Number of input, hidden and output nodes
	NInputs, NHiddens, NOutputs int
	// Whether it is regression or not
	Regression bool
	// Activations for nodes
	InputActivations, HiddenActivations, OutputActivations []*seal.Ciphertext
	// ElmanRNN contexts
	Contexts [][]*seal.Ciphertext
	// Weights
	InputWeights, OutputWeights [][]*seal.Ciphertext
	// Last change in weights for momentum
	InputChanges, OutputChanges [][]*seal.Ciphertext
}

/*
Initialize the neural network;

the 'inputs' value is the number of inputs the network will have,
the 'hiddens' value is the number of hidden nodes and
the 'outputs' value is the number of the outputs of the network.
*/
func (nn *FeedForward) Init(inputs, hiddens, outputs int) {

	nn.NInputs = inputs + 1   // +1 for bias
	nn.NHiddens = hiddens + 1 // +1 for bias
	nn.NOutputs = outputs

	nn.InputActivations = nn.vector(nn.NInputs, 1.0)
	nn.HiddenActivations = nn.vector(nn.NHiddens, 1.0)
	nn.OutputActivations = nn.vector(nn.NOutputs, 1.0)

	nn.InputWeights = nn.matrix(nn.NInputs, nn.NHiddens)
	nn.OutputWeights = nn.matrix(nn.NHiddens, nn.NOutputs)

	for i := 0; i < nn.NInputs; i++ {
		for j := 0; j < nn.NHiddens; j++ {
			nn.InputWeights[i][j] = nn.random(-1, 1)
		}
	}

	for i := 0; i < nn.NHiddens; i++ {
		for j := 0; j < nn.NOutputs; j++ {
			nn.OutputWeights[i][j] = nn.random(-1, 1)
		}
	}

	nn.InputChanges = nn.matrix(nn.NInputs, nn.NHiddens)
	nn.OutputChanges = nn.matrix(nn.NHiddens, nn.NOutputs)
}

/*
Set the number of contexts to add to the network.

By default the network do not have any context so it is a simple Feed Forward network,
when contexts are added the network behaves like an Elman's SRN (Simple Recurrent Network).

The first parameter (nContexts) is used to indicate the number of contexts to be used,
the second parameter (initValues) can be used to create custom initialized contexts.

If 'initValues' is set, the first parameter 'nContexts' is ignored and
the contexts provided in 'initValues' are used.

When using 'initValues' note that contexts must have the same size of hidden nodes + 1 (bias node).
*/
func (nn *FeedForward) SetContexts(nContexts int, initValues [][]*seal.Ciphertext) {
	if initValues == nil {
		initValues = make([][]*seal.Ciphertext, nContexts)

		for i := 0; i < nContexts; i++ {
			initValues[i] = nn.vector(nn.NHiddens, 0.5)
		}
	}

	nn.Contexts = initValues
}

/*
The Update method is used to activate the Neural Network.

Given an array of inputs, it returns an array, of length equivalent of number of outputs, with values ranging from 0 to 1.
*/
func (nn *FeedForward) Update(inputs []*seal.Ciphertext) []*seal.Ciphertext {
	if len(inputs) != nn.NInputs-1 {
		log.Fatal("Error: wrong number of inputs")
	}

	for i := 0; i < nn.NInputs-1; i++ {
		nn.InputActivations[i] = inputs[i]
	}

	for i := 0; i < nn.NHiddens-1; i++ {
		var sum *seal.Ciphertext

		for j := 0; j < nn.NInputs; j++ {
			elem := nn.Evaluator.Multiply(nn.InputActivations[j], nn.InputWeights[j][i])
			if sum == nil {
				sum = elem
			} else {
				nn.Evaluator.AddInplace(sum, elem)
			}
		}

		// compute contexts sum
		for k := 0; k < len(nn.Contexts); k++ {
			for j := 0; j < nn.NHiddens-1; j++ {
				nn.Evaluator.AddInplace(sum, nn.Contexts[k][j])
			}
		}

		nn.HiddenActivations[i] = nn.sigmoid(sum)
	}

	// update the contexts
	if len(nn.Contexts) > 0 {
		for i := len(nn.Contexts) - 1; i > 0; i-- {
			nn.Contexts[i] = nn.Contexts[i-1]
		}
		nn.Contexts[0] = nn.HiddenActivations
	}

	for i := 0; i < nn.NOutputs; i++ {
		var sum *seal.Ciphertext
		for j := 0; j < nn.NHiddens; j++ {
			elem := nn.Evaluator.Multiply(nn.HiddenActivations[j], nn.OutputWeights[j][i])
			if sum == nil {
				sum = elem
			} else {
				nn.Evaluator.AddInplace(sum, elem)
			}
		}

		nn.OutputActivations[i] = nn.sigmoid(sum)
	}

	return nn.OutputActivations
}

/*
The BackPropagate method is used, when training the Neural Network,
to back propagate the errors from network activation.
*/
func (nn *FeedForward) BackPropagate(targets []*seal.Ciphertext, lRate, mFactor float64) *seal.Ciphertext {
	if len(targets) != nn.NOutputs {
		log.Fatal("Error: wrong number of target values")
	}

	lRatePlain := nn.Encoder.Encode(lRate)
	mFactorPlain := nn.Encoder.Encode(mFactor)

	outputDeltas := nn.vector(nn.NOutputs, 0.0)
	for i := 0; i < nn.NOutputs; i++ {
		outputDeltas[i] = nn.Evaluator.Multiply(
			nn.dsigmoid(nn.OutputActivations[i]),
			nn.Evaluator.Sub(targets[i], nn.OutputActivations[i]))
	}

	hiddenDeltas := nn.vector(nn.NHiddens, 0.0)
	for i := 0; i < nn.NHiddens; i++ {
		e := nn.Encryptor.Encrypt(nn.Encoder.Encode(0))

		for j := 0; j < nn.NOutputs; j++ {
			nn.Evaluator.AddInplace(e,
				nn.Evaluator.Multiply(outputDeltas[j], nn.OutputWeights[i][j]))
		}

		hiddenDeltas[i] = nn.Evaluator.Multiply(nn.dsigmoid(nn.HiddenActivations[i]), e)
	}

	for i := 0; i < nn.NHiddens; i++ {
		for j := 0; j < nn.NOutputs; j++ {
			change := nn.Evaluator.Multiply(outputDeltas[j], nn.HiddenActivations[i])
			nn.Evaluator.AddInplace(nn.OutputWeights[i][j],
				nn.Evaluator.MultiplyPlain(change, lRatePlain))
			nn.Evaluator.AddInplace(nn.OutputWeights[i][j],
				nn.Evaluator.MultiplyPlain(nn.OutputChanges[i][j], mFactorPlain))
			nn.OutputChanges[i][j] = change
		}
	}

	for i := 0; i < nn.NInputs; i++ {
		for j := 0; j < nn.NHiddens; j++ {
			change := nn.Evaluator.Multiply(hiddenDeltas[j], nn.InputActivations[i])
			nn.Evaluator.AddInplace(nn.InputWeights[i][j],
				nn.Evaluator.MultiplyPlain(change, lRatePlain))
			nn.Evaluator.AddInplace(nn.InputWeights[i][j],
				nn.Evaluator.MultiplyPlain(nn.InputChanges[i][j], mFactorPlain))
			nn.InputChanges[i][j] = change
		}
	}

	e := nn.Encryptor.Encrypt(nn.Encoder.Encode(0))

	halve := nn.Encoder.Encode(0.5)

	for i := 0; i < len(targets); i++ {
		v := nn.Evaluator.Sub(targets[i], nn.OutputActivations[i])
		nn.Evaluator.SquareInplace(v)
		nn.Evaluator.MultiplyPlainInplace(v, halve)
		nn.Evaluator.AddInplace(e, v)
	}

	return e
}

/*
This method is used to train the Network, it will run the training operation for 'iterations' times
and return the computed errors when training.
*/
func (nn *FeedForward) Train(patterns [][][]*seal.Ciphertext, iterations int, lRate, mFactor float64, debug bool) []*seal.Ciphertext {
	errors := make([]*seal.Ciphertext, iterations)

	for i := 0; i < iterations; i++ {
		e := nn.Encryptor.Encrypt(nn.Encoder.Encode(0))
		for _, p := range patterns {
			nn.Update(p[0])

			tmp := nn.BackPropagate(p[1], lRate, mFactor)
			nn.Evaluator.AddInplace(e, tmp)
		}

		errors[i] = e
	}

	return errors
}

func (nn *FeedForward) Test(patterns [][][]*seal.Ciphertext) {
	for _, p := range patterns {
		fmt.Println(p[0], "->", nn.Update(p[0]), " : ", p[1])
	}
}
