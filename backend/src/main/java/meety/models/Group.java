package meety.models;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import meety.dtos.GroupDto;

import java.util.Date;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "group_entity")
public class Group {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String description;

    @OneToMany(mappedBy = "group", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference
    @ToString.Exclude
    private List<GroupMember> members;

    @ManyToOne
    @JoinColumn(name = "created_by_id")
    @ToString.Exclude
    private User createdBy;

    private Date createdAt;
    private Boolean isPublic;

    public Group(GroupDto dto) {
        name = dto.getName();
        description = dto.getDescription();
        members = List.of();
        isPublic = true;
        createdAt = new Date();
    }
}
