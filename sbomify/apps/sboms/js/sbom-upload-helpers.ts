export const MAX_SBOM_SIZE = 100 * 1024 * 1024;
export const ALLOWED_MIME_TYPES = ['application/json', 'text/plain'];
export const ALLOWED_EXTENSIONS = ['.json', '.spdx', '.cdx'];

export type UploadBomType = 'sbom' | 'vex'

export function bomTypeLabel(bomType: UploadBomType): string {
    return bomType === 'vex' ? 'VEX' : 'SBOM'
}

export function buildUploadEndpoint(componentId: string, bomType: UploadBomType): string {
    // The default SBOM case must omit bom_type: the server's CBOM
    // auto-detection only runs when the caller leaves it unset.
    const base = `/api/v1/sboms/upload-file/${componentId}`
    return bomType === 'sbom' ? base : `${base}?bom_type=${encodeURIComponent(bomType)}`
}

export function validateUploadFile(file: File, bomType: UploadBomType): string | null {
    if (file.size > MAX_SBOM_SIZE) {
        return 'File size must be 100MB or smaller'
    }

    const fileExtension = file.name.toLowerCase().slice(file.name.lastIndexOf('.'));
    const hasValidType = ALLOWED_MIME_TYPES.includes(file.type);
    const hasValidExtension = ALLOWED_EXTENSIONS.includes(fileExtension);

    if (!hasValidType && !hasValidExtension) {
        const allowed = bomType === 'vex' ? '.json, .cdx' : '.json, .spdx, .cdx'
        return `Please select a valid ${bomTypeLabel(bomType)} file (${allowed})`
    }

    // Catch both bare ".spdx" and the common ".spdx.json" naming. The server
    // inspects the content either way; this just fails obvious cases early.
    if (bomType === 'vex' && /\.spdx(\.|$)/.test(file.name.toLowerCase())) {
        return 'SPDX files are SBOM-only; a VEX must be CycloneDX, OpenVEX, or CSAF (.json, .cdx)'
    }

    return null
}
