package proxy

func (s *Server) AllAllowlists() map[string]*Allowlist {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*Allowlist, len(s.allowlists))
	for k, v := range s.allowlists {
		result[k] = v
	}
	return result
}

// AllDenylists returns a snapshot of the container→denylist map for persistence.

func (s *Server) AllDenylists() map[string]*Denylist {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*Denylist, len(s.denylists))
	for k, v := range s.denylists {
		result[k] = v
	}
	return result
}

// LoadAllowlistsFromDir loads persisted allowlists into the server.
// Existing in-memory entries are kept; persisted domains are merged in.

func (s *Server) LoadAllowlistsFromDir(dataDir string) error {
	loaded, err := LoadAllowlists(dataDir)
	if err != nil {
		return err
	}
	for container, al := range loaded {
		for _, d := range al.UserDomains() {
			s.GetAllowlist(container).Add(d)
		}
	}
	return nil
}

// SaveAllowlistsToDir persists all per-container allowlists to dataDir.

func (s *Server) SaveAllowlistsToDir(dataDir string) error {
	return SaveAllowlists(dataDir, s.AllAllowlists())
}

// LoadDenylistsFromDir loads persisted denylists into the server.

func (s *Server) LoadDenylistsFromDir(dataDir string) error {
	loaded, err := LoadDenylists(dataDir)
	if err != nil {
		return err
	}
	for container, dl := range loaded {
		for _, d := range dl.List() {
			s.GetDenylist(container).Add(d)
		}
	}
	return nil
}

// SaveDenylistsToDir persists all per-container denylists to dataDir.

func (s *Server) SaveDenylistsToDir(dataDir string) error {
	return SaveDenylists(dataDir, s.AllDenylists())
}
