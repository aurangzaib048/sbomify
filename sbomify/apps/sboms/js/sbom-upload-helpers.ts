export const MAX_SBOM_SIZE = 100 * 1024 * 1024;
export const ALLOWED_MIME_TYPES = ['application/json', 'text/plain'];
export const ALLOWED_EXTENSIONS = ['.json', '.spdx', '.cdx'];

export type UploadBomType = 'sbom' | 'vex'

export function bomTypeLabel(bomType: UploadBomType): string {
    return bomType === 'vex' ? 'VEX' : 'SBOM'
}

export function buildUploadEndpoint(componentId: string, bomType: UploadBomType): string {
    return `/api/v1/sboms/upload-file/${componentId}?bom_type=${encodeURIComponent(bomType)}`
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

    if (bomType === 'vex' && fileExtension === '.spdx') {
        return 'VEX documents must be CycloneDX (.json or .cdx)'
    }

    return null
}
