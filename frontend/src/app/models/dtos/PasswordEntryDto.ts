export interface PasswordEntryDto {
  id: number;
  name: string;
  username: string;
  url?: string | null;
  notes?: string | null;
  categoryId?: number | null;
}
