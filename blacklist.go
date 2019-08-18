package auth

// BlackList ...
type BlackList interface {
	AddKey(string) error
	Contains(string) (bool, error)
}
