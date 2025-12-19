package vaultWeb.dtos.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ChangePasswordRequest {

  @NotBlank(message = "Current password is required")
  private String currentPassword;

  @NotBlank(message = "New password cannot be blank")
  @Size(min = 8, message = "Password must be at least 8 characters long")
  @Pattern(
          regexp = "^(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).*$",
          message = "Password must contain at least one uppercase letter, one digit, and one special character")
  private String newPassword;
}
