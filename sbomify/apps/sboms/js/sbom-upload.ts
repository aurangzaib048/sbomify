import Alpine from '../../core/js/alpine-init'
import { showSuccess, showError } from '../../core/js/alerts'
import { getCsrfToken } from '../../core/js/csrf'
import { bomTypeLabel, buildUploadEndpoint, validateUploadFile, type UploadBomType } from './sbom-upload-helpers'

interface SbomUploadState {
    expanded: boolean
    isDragOver: boolean
    isUploading: boolean
    componentId: string
    bomType: UploadBomType
    abortController: AbortController | null
    readonly bomTypeLabel: string
    handleDrop: (event: DragEvent) => void
    handleFileSelect: (event: Event) => void
    validateFile: (file: File) => string | null
    uploadFile: (file: File) => Promise<void>
    cleanup: () => void
}

export function registerSbomUpload(): void {
    Alpine.data('sbomUpload', (componentId: string, hasSboms: boolean = false): SbomUploadState => ({
        expanded: !hasSboms,
        isDragOver: false,
        isUploading: false,
        componentId: componentId,
        bomType: 'sbom' as UploadBomType,
        abortController: null,

        get bomTypeLabel(): string {
            return bomTypeLabel(this.bomType)
        },

        validateFile(file: File): string | null {
            return validateUploadFile(file, this.bomType)
        },

        async uploadFile(file: File): Promise<void> {
            const validationError = this.validateFile(file)
            if (validationError) {
                showError(validationError)
                return
            }

            if (this.isUploading) {
                showError('An upload is already in progress. Please wait.')
                return
            }

            this.isUploading = true
            this.abortController = new AbortController()

            try {
                const formData = new FormData()
                formData.append('sbom_file', file)
                formData.append('component_id', this.componentId)

                const csrfToken = getCsrfToken()

                const response = await fetch(buildUploadEndpoint(this.componentId, this.bomType), {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-CSRFToken': csrfToken
                    },
                    signal: this.abortController.signal
                })

                let data: Record<string, unknown> = {};
                const contentType = response.headers.get('content-type');

                if (contentType?.includes('application/json')) {
                    try {
                        data = await response.json();
                    } catch {
                        // JSON parse failed, continue with empty data
                    }
                }

                if (response.ok) {
                    showSuccess(`${this.bomTypeLabel} uploaded successfully! Reloading page...`)
                    window.dispatchEvent(new CustomEvent('sbom-uploaded'))
                } else {
                    const errorMessage = (data.detail as string) || `Upload failed with status ${response.status}`
                    showError(errorMessage)
                }
            } catch (error) {
                if (error instanceof Error) {
                    if (error.name === 'AbortError') {
                        showError('Upload was cancelled.')
                    } else {
                        showError(`Network error: ${error.message}`)
                    }
                } else {
                    showError('An unexpected error occurred. Please try again.')
                }
            } finally {
                this.isUploading = false
                this.abortController = null
            }
        },

        handleDrop(event: DragEvent): void {
            event.preventDefault();
            this.isDragOver = false;

            if (this.isUploading) {
                return;
            }

            const files = event.dataTransfer?.files;
            if (files?.[0]) {
                this.uploadFile(files[0]);
            }
        },

        handleFileSelect(event: Event): void {
            const target = event.target as HTMLInputElement;

            if (this.isUploading) {
                showError('An upload is already in progress. Please wait.')
                target.value = '';
                return;
            }

            const files = target.files;
            if (files?.[0]) {
                this.uploadFile(files[0]);
            }
            target.value = '';
        },

        cleanup(): void {
            if (this.abortController) {
                this.abortController.abort()
                this.abortController = null
            }
        }
    }))
}
