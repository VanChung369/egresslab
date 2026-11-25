package helperipc

import "github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"

// OpListLabs returns the helper's bookkeeping, not a fresh kernel check (that is VerifyLab).
const OpListLabs = "ListLabs"

func validLabListResponse(req Request, resp Response) bool {
	if req.Operation != OpListLabs || !resp.OK {
		return resp.Labs == nil
	}

	if len(resp.Labs) > maxManagedLabs {
		return false
	}

	profiles := make(map[string]bool)
	namespaces := make(map[string]bool)

	for _, lab := range resp.Labs {
		if !helperauth.ValidProfileID(lab.ProfileID) ||
			!helperauth.ValidLabNamespace(lab.Namespace) ||
			(lab.State != LabSealed && lab.State != LabFaulted && lab.State != LabTunnelConfigured) ||
			profiles[lab.ProfileID] ||
			namespaces[lab.Namespace] {
			return false
		}

		profiles[lab.ProfileID] = true
		namespaces[lab.Namespace] = true
	}

	return true
}
