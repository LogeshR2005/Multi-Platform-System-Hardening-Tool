package com.backend.Backend.model;

import jakarta.persistence.*;


import lombok.*;

import java.time.Instant;
import java.time.LocalDateTime;

@Entity
@Table(name = "alerts")
@Data
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String agentId;      // Optional: which agent triggered it

    private String severity;     // high / medium / low

    private String message;

    private LocalDateTime createdAt;

    private Instant time;

    public Alert(Long id, String agentId, String severity, String message, LocalDateTime createdAt, Instant time) {
        this.id = id;
        this.agentId = agentId;
        this.severity = severity;
        this.message = message;
        this.createdAt = createdAt;
        this.time = time;
    }

    public Alert(){

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

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getTime() {
        return time;
    }

    public void setTime(Instant time) {
        this.time = time;
    }
}
