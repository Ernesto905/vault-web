import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { FolderDto } from '../../models/dtos/FolderDto';
import { CloudService } from '../../services/cloud.service';

interface Breadcrumb {
  name: string;
  path: string;
}

@Component({
  selector: 'app-cloud',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './cloud.component.html',
  styleUrls: ['./cloud.component.scss'],
})
export class CloudComponent implements OnInit {
  currentFolder?: FolderDto;
  loading = true;
  error?: string;
  breadcrumbs: Breadcrumb[] = [];
  rootPath = '';
  showCreateDropdown = false;
  showFileEditor = false;
  editingFile: any = null;
  newFileName = '';
  fileContent = '';
  private draggedPath: string | null = null;
  private draggedIsFolder = false;

  constructor(private cloudService: CloudService) {}

  ngOnInit(): void {
    this.loadRootFolder();
  }

  loadRootFolder() {
    this.loading = true;
    this.error = undefined;
    this.cloudService.getRootFolder().subscribe({
      next: (folder) => {
        this.currentFolder = folder;
        this.rootPath = folder.path;
        this.updateBreadcrumbs(folder.path);
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Error loading root folder';
        this.loading = false;
      },
    });
  }

  reloadRootFolder() {
    this.loadRootFolder();
  }

  navigateToFolder(folderPath?: string) {
    this.loading = true;
    const relativePath = this.getRelativePath(folderPath || this.rootPath);
    this.cloudService.getFolderByPath(relativePath).subscribe({
      next: (folder) => {
        this.currentFolder = folder;
        this.updateBreadcrumbs(folder.path);
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Error navigating to folder';
        this.loading = false;
      },
    });
  }

  navigateToRoot() {
    this.navigateToFolder(this.rootPath);
  }

  updateBreadcrumbs(currentPath: string) {
    this.breadcrumbs = [];
    const relativePath = currentPath
      .replace(this.rootPath, '')
      .replace(/^[\\/]/, '');
    if (!relativePath) return;
    const parts = relativePath.split(/[\\/]/);
    let accumulatedPath = this.rootPath;
    parts.forEach((part) => {
      accumulatedPath = accumulatedPath + '/' + part;
      this.breadcrumbs.push({ name: part, path: accumulatedPath });
    });
  }

  getRelativePath(fullPath: string): string {
    return fullPath === this.rootPath
      ? '/'
      : fullPath.replace(this.rootPath + '/', '');
  }

  createNewFolder() {
    const folderName = prompt('Enter folder name:');
    if (!folderName) return;
    const currentPath = this.getRelativePath(this.currentFolder?.path || '/');
    this.cloudService.createFolder(currentPath, folderName).subscribe({
      next: () => this.navigateToFolder(this.currentFolder?.path),
      error: (err) => alert('Error creating folder: ' + err.message),
    });
  }

  createNewFile() {
    this.editingFile = null;
    this.newFileName = '';
    this.fileContent = '';
    this.showFileEditor = true;
  }

  editFile(file: any) {
    const nonEditableExtensions = [
      'pdf',
      'png',
      'jpg',
      'jpeg',
      'gif',
      'bmp',
      'mp4',
      'mp3',
      'avi',
      'mov',
      'wmv',
      'flv',
      'mkv',
      'zip',
      'rar',
      '7z',
      'tar',
      'gz',
    ];
    const ext = file.name.split('.').pop()?.toLowerCase();

    if (!ext || nonEditableExtensions.includes(ext)) {
      alert('This file cannot be edited. You can download it instead.');
      this.downloadFile(file);
      return;
    }

    this.editingFile = file;
    this.newFileName = file.name;
    const relativePath = this.getRelativePath(file.path);

    this.cloudService.getFileContent(relativePath).subscribe({
      next: (content) => {
        this.fileContent = content;
        this.showFileEditor = true;
      },
      error: (err) => {
        this.editingFile = null;
        alert('Error loading file: ' + err.message);
      },
    });
  }

  saveFile() {
    if (!this.newFileName.trim()) return;
    const currentPath = this.getRelativePath(this.currentFolder?.path || '/');
    const fileBlob = new Blob([this.fileContent], { type: 'text/plain' });
    const file = new File([fileBlob], this.newFileName);
    this.uploadFile(currentPath, file);
  }

  uploadFile(folderPath: string, file: File) {
    this.cloudService.uploadFile(folderPath, file).subscribe({
      next: () => {
        this.navigateToFolder(this.currentFolder?.path);
        this.showFileEditor = false;
      },
      error: (err) => alert('Error uploading file: ' + err.message),
    });
  }

  onFileSelected(event: any) {
    const file: File = event.target.files[0];
    if (!file) return;
    const currentPath = this.getRelativePath(this.currentFolder?.path || '/');
    this.uploadFile(currentPath, file);
  }

  deleteFolder(folderPath: string) {
    if (!confirm('Do you really want to delete this folder?')) return;
    const relativePath = this.getRelativePath(folderPath);
    this.cloudService.deleteFolder(relativePath).subscribe({
      next: () => this.navigateToFolder(this.currentFolder?.path),
      error: (err) => alert('Error deleting folder: ' + err.message),
    });
  }

  deleteFile(filePath: string) {
    if (!confirm('Do you really want to delete this file?')) return;
    const relativePath = this.getRelativePath(filePath);
    this.cloudService.deleteFile(relativePath).subscribe({
      next: () => this.navigateToFolder(this.currentFolder?.path),
      error: (err) => alert('Error deleting file: ' + err.message),
    });
  }

  downloadFile(file: any) {
    const relativePath = this.getRelativePath(file.path);
    this.cloudService.getFileBlob(relativePath).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.name;
        a.click();
        window.URL.revokeObjectURL(url);
      },
      error: (err) => alert('Error downloading file: ' + err.message),
    });
  }

  formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  onDragStart(event: DragEvent, path: string, isFolder: boolean) {
    this.draggedPath = path;
    this.draggedIsFolder = isFolder;
    if (event.dataTransfer) {
      event.dataTransfer.setData('text/plain', path);
      event.dataTransfer.effectAllowed = 'move';
    }
  }

  onDragOver(event: DragEvent) {
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
  }

  async onDrop(event: DragEvent, targetFolder: any, isFolder: boolean) {
    event.preventDefault();
    if (!this.draggedPath) return;
    const targetPath = targetFolder?.path || this.currentFolder?.path;
    if (!targetPath || this.draggedPath === targetPath) return;
    const relativeSource = this.getRelativePath(this.draggedPath);
    const relativeTarget = this.getRelativePath(targetPath);
    try {
      if (this.draggedIsFolder) {
        await this.cloudService
          .renameOrMoveFolder(
            relativeSource,
            `${relativeTarget}/${this.getNameFromPath(this.draggedPath)}`,
          )
          .toPromise();
      } else {
        await this.cloudService
          .renameOrMoveFile(
            relativeSource,
            `${relativeTarget}/${this.getNameFromPath(this.draggedPath)}`,
          )
          .toPromise();
      }
      this.reloadRootFolder();
    } catch (err: any) {
      alert('Error moving item: ' + err.message);
    } finally {
      this.draggedPath = null;
    }
  }

  onBreadcrumbDragOver(event: DragEvent) {
    event.preventDefault();
  }

  async onBreadcrumbDrop(event: DragEvent, targetPath: string) {
    event.preventDefault();
    if (!this.draggedPath) return;
    const relativeSource = this.getRelativePath(this.draggedPath);
    const relativeTarget = this.getRelativePath(targetPath);
    try {
      if (this.draggedIsFolder) {
        await this.cloudService
          .renameOrMoveFolder(
            relativeSource,
            `${relativeTarget}/${this.getNameFromPath(this.draggedPath)}`,
          )
          .toPromise();
      } else {
        await this.cloudService
          .renameOrMoveFile(
            relativeSource,
            `${relativeTarget}/${this.getNameFromPath(this.draggedPath)}`,
          )
          .toPromise();
      }
      this.reloadRootFolder();
    } catch (err: any) {
      alert('Error moving item: ' + err.message);
    } finally {
      this.draggedPath = null;
    }
  }

  getNameFromPath(path: string): string {
    const parts = path.split('/');
    return parts[parts.length - 1];
  }

  renameFolder(folder: any) {
    const newName = prompt('Enter new folder name:', folder.name);
    if (!newName || newName.trim() === '' || newName === folder.name) return;
    const relativeSource = this.getRelativePath(folder.path);
    const targetPath = folder.path.substring(0, folder.path.lastIndexOf('/'));
    const relativeTarget = this.getRelativePath(targetPath);
    this.cloudService
      .renameOrMoveFolder(relativeSource, `${relativeTarget}/${newName}`)
      .subscribe({
        next: () => this.navigateToFolder(this.currentFolder?.path),
        error: (err) => alert('Error renaming folder: ' + err.message),
      });
  }
}
