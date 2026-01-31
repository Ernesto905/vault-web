export interface PasswordEntryCreateRequestDto {
  name: string;
  username: string;
  password: string;
  url?: string | null;
  notes?: string | null;
  categoryId?: number | null;
}
