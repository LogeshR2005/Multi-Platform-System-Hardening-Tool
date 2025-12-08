package com.backend.Backend.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "hardening_jobs")
public class HardeningJob {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String agentId;       // Link back to target / agent

    private String level;         // Easy / Moderate / Strict

    private String status;        // success / failed

    private LocalDateTime runAt;


    public HardeningJob(Long id, String agentId, String level, String status, LocalDateTime runAt) {
        this.id = id;
        this.agentId = agentId;
        this.level = level;
        this.status = status;
        this.runAt = runAt;
    }

    public HardeningJob(){

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAgentId() {
        return agentId;
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public LocalDateTime getRunAt() {
        return runAt;
    }

    public void setRunAt(LocalDateTime runAt) {
        this.runAt = runAt;
    }
}
