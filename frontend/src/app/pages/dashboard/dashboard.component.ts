import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import {
  AbstractControl,
  FormBuilder,
  FormGroup,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { DashboardService } from '../../services/dashboard.service';
import { UserDashboardDto } from '../../models/dtos/UserDashboardDto';
import { AuthService } from '../../services/auth.service';

interface StatHighlight {
  label: string;
  value: string;
  helper: string;
  accent: 'cyan' | 'amber' | 'emerald' | 'rose';
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent implements OnInit {
  dashboard?: UserDashboardDto;
  isLoading = true;
  error: string | null = null;
  statHighlights: StatHighlight[] = [];
  passwordForm: FormGroup;
  isSavingPassword = false;
  passwordSuccess = '';
  passwordError = '';
  private readonly passwordComplexity =
    /(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+/;

  constructor(
    private dashboardService: DashboardService,
    private fb: FormBuilder,
    private authService: AuthService,
  ) {
    this.passwordForm = this.createPasswordForm();
  }

  ngOnInit(): void {
    this.loadDashboard();
  }

  retry(): void {
    this.loadDashboard(true);
  }

  trackById(_: number, item: { id: number }): number {
    return item?.id ?? 0;
  }

  get pf(): { [key: string]: AbstractControl } {
    return this.passwordForm.controls;
  }

  submitPasswordChange(): void {
    this.passwordSuccess = '';
    this.passwordError = '';

    if (this.passwordForm.invalid) {
      this.passwordForm.markAllAsTouched();
      return;
    }

    const { currentPassword, newPassword } = this.passwordForm.value;
    if (!currentPassword || !newPassword) {
      return;
    }

    this.isSavingPassword = true;
    this.authService.changePassword(currentPassword, newPassword).subscribe({
      next: () => {
        this.isSavingPassword = false;
        this.passwordSuccess = 'Password updated successfully.';
        this.passwordForm.reset();
        this.passwordForm.markAsPristine();
        this.passwordForm.markAsUntouched();
      },
      error: (error) => {
        this.isSavingPassword = false;
        const serverMessage =
          typeof error?.error === 'string'
            ? error.error
            : error?.error?.message;
        this.passwordError =
          serverMessage ||
          'Update failed. Please try again.';
      },
    });
  }

  isDeadlineActive(deadline: string | null): boolean {
    if (!deadline) {
      return true;
    }
    return new Date(deadline).getTime() >= Date.now();
  }

  private loadDashboard(isRetry = false): void {
    if (!isRetry) {
      this.isLoading = true;
      this.error = null;
    }

    this.dashboardService.getDashboard().subscribe({
      next: (data) => {
        this.dashboard = data;
        this.isLoading = false;
        this.error = null;
        this.buildHighlights(data);
      },
      error: () => {
        this.isLoading = false;
        this.error = 'Failed to load the dashboard.';
      },
    });
  }

  private buildHighlights(data: UserDashboardDto): void {
    const messages = Intl.NumberFormat('en-US').format(
      data.profile.messagesSent,
    );
    this.statHighlights = [
      {
        label: 'Groups',
        value: data.profile.groupCount.toString(),
        helper: 'active communities',
        accent: 'cyan',
      },
      {
        label: 'Private chats',
        value: data.profile.privateChatCount.toString(),
        helper: 'ongoing conversations',
        accent: 'amber',
      },
      {
        label: 'Messages sent',
        value: messages,
        helper: 'total',
        accent: 'emerald',
      },
      {
        label: 'Open polls',
        value: data.polls.length.toString(),
        helper: 'need attention',
        accent: 'rose',
      },
    ];
  }

  private createPasswordForm(): FormGroup {
    return this.fb.group(
      {
        currentPassword: ['', [Validators.required]],
        newPassword: [
          '',
          [
            Validators.required,
            Validators.minLength(8),
            Validators.pattern(this.passwordComplexity),
          ],
        ],
        confirmPassword: ['', [Validators.required]],
      },
      { validators: this.passwordMatchValidator.bind(this) },
    );
  }

  private passwordMatchValidator(
    control: AbstractControl,
  ): ValidationErrors | null {
    const newPassword = control.get('newPassword')?.value;
    const confirmPassword = control.get('confirmPassword')?.value;

    if (!newPassword || !confirmPassword) {
      return null;
    }

    return newPassword === confirmPassword ? null : { mismatch: true };
  }
}
