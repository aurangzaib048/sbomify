import { registerAlpineComponent } from '../../core/js/alpine-components';
import { EU_COUNTRIES, EU_COUNTRY_NAMES } from './eu-countries';
import { getAssessmentId, saveStepAndNavigate } from './cra-shared';

interface ProductInfo {
  id: string;
  name: string;
  description: string;
  release_date: string | null;
  end_of_support: string | null;
  end_of_life: string | null;
}

interface ManufacturerInfo {
  name: string;
  address: string;
  email: string;
  website_urls: string[];
}

// Maps category → default conformity description (for initial display before save)
const CATEGORY_CONFORMITY_MAP: Record<string, string> = {
  default: 'Module A (Internal production control)',
  class_i: 'Module A or EUCC scheme',
  class_ii: 'Module B+C or Module H or EUCC scheme',
  critical: 'EUCC scheme (mandatory third-party)',
};

// Maps procedure key → human-readable label (matches backend ConformityProcedure choices)
const PROCEDURE_LABEL_MAP: Record<string, string> = {
  module_a: 'Module A (Internal production control)',
  module_b_c: 'Module B+C (EU-type examination)',
  module_h: 'Module H (Full quality assurance)',
  eucc: 'EUCC scheme (EU Cybersecurity Certification)',
};

function craStep1() {
  return {
    assessmentId: '',
    product: {} as ProductInfo,
    manufacturer: null as ManufacturerInfo | null,
    // Wizard-side mirror of the backend placeholder check so the UI can
    // warn the operator BEFORE they reach Step 5 and discover the
    // DoC rendered "[Manufacturer Name — not configured]". Backend
    // source of truth: services._manufacturer_policy.is_placeholder_manufacturer.
    manufacturerIsPlaceholder: false as boolean,
    category: 'default',
    isOpenSourceSteward: false,
    // EN 18031 applicability flags (issue #905). Orthogonal to the
    // CRA risk-tier ``category`` — a Class I product may or may not
    // be radio equipment. Ticking ``isRadioEquipment`` triggers
    // EN 18031-1 in the DoC; pairing it with the scope flags below
    // pulls in EN 18031-2 / -3.
    isRadioEquipment: false,
    processesPersonalData: false,
    handlesFinancialValue: false,
    euMarkets: [] as string[],
    supportPeriodEnd: '',
    intendedUse: '',
    conformityAssessmentProcedure: '',
    isSaving: false,
    euCountries: EU_COUNTRIES,
    euCountryNames: EU_COUNTRY_NAMES,

    init() {
      const data = window.parseJsonScript('step-data');
      if (data) {
        const d = data as Record<string, unknown>;
        this.product = (d.product as ProductInfo) || {};
        this.manufacturer = (d.manufacturer as ManufacturerInfo) || null;
        this.manufacturerIsPlaceholder = Boolean(d.manufacturer_is_placeholder);
        this.category = (d.product_category as string) || 'default';
        this.isOpenSourceSteward = !!(d.is_open_source_steward);
        this.isRadioEquipment = !!(d.is_radio_equipment);
        this.processesPersonalData = !!(d.processes_personal_data);
        this.handlesFinancialValue = !!(d.handles_financial_value);
        this.euMarkets = (d.target_eu_markets as string[]) || [];
        this.supportPeriodEnd = (d.support_period_end as string) || '';
        this.intendedUse = (d.intended_use as string) || '';
        this.conformityAssessmentProcedure =
          (d.conformity_assessment_procedure as string) || '';
      }
      this.assessmentId = getAssessmentId();
      // EN 18031-2/-3 only apply to radio equipment (issue #905).
      // When the operator un-ticks ``isRadioEquipment`` the two
      // dependent scope flags must follow — the template disables
      // them but the bound values survive, which persists an
      // inconsistent state and renders as "disabled-but-checked"
      // on the next page load. The backend's _save_step_1 already
      // clears these defensively; this mirror prevents the stale
      // tick from reaching the save call in the first place.
      // Uses Alpine's $watch, typed here via `this` cast because
      // registerAlpineComponent doesn't propagate Alpine's magics.
      (this as unknown as { $watch: (prop: string, cb: (val: unknown) => void) => void }).$watch(
        'isRadioEquipment',
        (val: unknown) => {
          if (!val) {
            this.processesPersonalData = false;
            this.handlesFinancialValue = false;
          }
        },
      );
    },

    get canContinue(): boolean {
      // CRA Annex V item 2 requires the manufacturer's legal name on
      // the generated DoC. When the team profile still carries a
      // placeholder (or none) we refuse to advance past Step 1 — this
      // is the wizard-side prevention that pairs with the render-time
      // safety net in document_generation_service._build_common_context.
      // Issue #908.
      if (this.manufacturerIsPlaceholder) return false;
      return !!this.category && this.euMarkets.length > 0 && !!this.supportPeriodEnd;
    },

    get conformityProcedure(): string {
      if (this.conformityAssessmentProcedure) {
        return PROCEDURE_LABEL_MAP[this.conformityAssessmentProcedure] || this.conformityAssessmentProcedure;
      }
      return CATEGORY_CONFORMITY_MAP[this.category] || CATEGORY_CONFORMITY_MAP.default;
    },

    get allMarketsSelected(): boolean {
      return this.euMarkets.length === EU_COUNTRIES.length;
    },

    toggleAllMarkets(): void {
      if (this.allMarketsSelected) {
        this.euMarkets = [];
      } else {
        this.euMarkets = [...EU_COUNTRIES];
      }
    },

    toggleMarket(code: string): void {
      const idx = this.euMarkets.indexOf(code);
      if (idx >= 0) {
        this.euMarkets.splice(idx, 1);
      } else {
        this.euMarkets.push(code);
      }
    },

    isMarketSelected(code: string): boolean {
      return this.euMarkets.includes(code);
    },

    async save(): Promise<void> {
      if (!this.canContinue || this.isSaving) return;
      await saveStepAndNavigate(this.assessmentId, 1, {
        product_category: this.category,
        is_open_source_steward: this.isOpenSourceSteward,
        is_radio_equipment: this.isRadioEquipment,
        processes_personal_data: this.processesPersonalData,
        handles_financial_value: this.handlesFinancialValue,
        target_eu_markets: this.euMarkets,
        support_period_end: this.supportPeriodEnd,
        intended_use: this.intendedUse,
      }, (v) => { this.isSaving = v; });
    },
  };
}

export function registerCraStep1(): void {
  registerAlpineComponent('craStep1', craStep1);
}
