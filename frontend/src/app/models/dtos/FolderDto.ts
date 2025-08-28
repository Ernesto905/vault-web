import { FileDto } from './FileDto';

export interface FolderDto {
  name: string;
  path: string;
  folders: FolderDto[];
  files: FileDto[];
}
