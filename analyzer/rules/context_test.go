package rules

import "testing"

func TestIdentityContextHelpers(t *testing.T) {
	tests := []struct {
		name                    string
		ctx                     *Context
		wantConcreteFamily      bool
		wantMeaningfulVendor    bool
		wantVendorWithoutFamily bool
		wantFamilyUncertain     bool
		wantWeak                bool
	}{
		{
			name: "high family",
			ctx: &Context{
				FamilyCandidate:    "tplink_controller",
				FamilyConfidence:   "high",
				VendorCandidate:    "TP-Link",
				VendorConfidence:   "high",
				CategoryCandidate:  "Controller",
				CategoryConfidence: "medium",
			},
			wantConcreteFamily:   true,
			wantMeaningfulVendor: true,
		},
		{
			name: "vendor only",
			ctx: &Context{
				VendorCandidate:  "TP-Link",
				VendorConfidence: "medium",
				FamilyCandidate:  "tplink_controller",
				FamilyConfidence: "low",
			},
			wantMeaningfulVendor:    true,
			wantVendorWithoutFamily: true,
			wantFamilyUncertain:     true,
		},
		{
			name: "weak identity",
			ctx: &Context{
				VendorCandidate:  "Apple",
				VendorConfidence: "low",
				FamilyConfidence: "unknown",
			},
			wantFamilyUncertain: true,
			wantWeak:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ctx.HasConcreteFamilyCandidate(); got != tt.wantConcreteFamily {
				t.Fatalf("HasConcreteFamilyCandidate=%t, want %t", got, tt.wantConcreteFamily)
			}
			if got := tt.ctx.HasMeaningfulVendorCandidate(); got != tt.wantMeaningfulVendor {
				t.Fatalf("HasMeaningfulVendorCandidate=%t, want %t", got, tt.wantMeaningfulVendor)
			}
			if got := tt.ctx.VendorWithoutConcreteFamily(); got != tt.wantVendorWithoutFamily {
				t.Fatalf("VendorWithoutConcreteFamily=%t, want %t", got, tt.wantVendorWithoutFamily)
			}
			if got := tt.ctx.FamilyIsUncertain(); got != tt.wantFamilyUncertain {
				t.Fatalf("FamilyIsUncertain=%t, want %t", got, tt.wantFamilyUncertain)
			}
			if got := tt.ctx.IdentityIsWeak(); got != tt.wantWeak {
				t.Fatalf("IdentityIsWeak=%t, want %t", got, tt.wantWeak)
			}
		})
	}
}
