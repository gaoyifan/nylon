package core

func nylonGc(n *Nylon) error {
	// scan for dead links
	for _, link := range n.RouterState.LinkList() {
		x := link.Endpoint.AsNylonEndpoint()
		if x == nil {
			continue
		}
		if !x.IsActive() {
			x.DynEP.Clear()
		}
		if !x.IsAlive() {
			n.Log.Debug("removed dead endpoint", "ep", x.DynEP.String(), "link", link.ID.String())
			n.RouterState.RemoveLink(link.ID)
		}
	}

	err := n.GcRouter()
	if err != nil {
		return err
	}

	return nil
}
