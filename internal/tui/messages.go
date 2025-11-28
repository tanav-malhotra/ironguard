package tui

import "time"

// MessageRole indicates who sent a chat message.
type MessageRole string

const (
	RoleUser   MessageRole = "user"
	RoleAI     MessageRole = "ai"
	RoleSystem MessageRole = "system"
	RoleTool   MessageRole = "tool"
)

// Message represents a single entry in the chat transcript.
type Message struct {
	Role      MessageRole
	Content   string
	Timestamp time.Time

	// For tool calls
	ToolName   string
	ToolInput  string
	ToolOutput string
	ToolError  string

	// For streaming
	IsStreaming bool
}

// NewUserMessage creates a user message.
func NewUserMessage(content string) Message {
	return Message{
		Role:      RoleUser,
		Content:   content,
		Timestamp: time.Now(),
	}
}

// NewAIMessage creates an AI response message.
func NewAIMessage(content string) Message {
	return Message{
		Role:      RoleAI,
		Content:   content,
		Timestamp: time.Now(),
	}
}

// NewSystemMessage creates a system/info message.
func NewSystemMessage(content string) Message {
	return Message{
		Role:      RoleSystem,
		Content:   content,
		Timestamp: time.Now(),
	}
}

// NewToolMessage creates a tool call message.
func NewToolMessage(toolName, input, output, errStr string) Message {
	return Message{
		Role:       RoleTool,
		Timestamp:  time.Now(),
		ToolName:   toolName,
		ToolInput:  input,
		ToolOutput: output,
		ToolError:  errStr,
	}
}

// StreamingAIMessage creates an AI message that is still being streamed.
func StreamingAIMessage() Message {
	return Message{
		Role:        RoleAI,
		Content:     "",
		Timestamp:   time.Now(),
		IsStreaming: true,
	}
}

