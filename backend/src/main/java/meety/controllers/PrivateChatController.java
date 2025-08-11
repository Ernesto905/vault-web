package meety.controllers;

import lombok.RequiredArgsConstructor;
import meety.dtos.ChatMessageDto;
import meety.dtos.PrivateChatDto;
import meety.models.ChatMessage;
import meety.models.PrivateChat;
import meety.repositories.ChatMessageRepository;
import meety.services.PrivateChatService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/private-chats")
@RequiredArgsConstructor
public class PrivateChatController {

    @Autowired
    private final PrivateChatService privateChatService;

    @Autowired
    private final ChatMessageRepository chatMessageRepository;

    @GetMapping("/between")
    public PrivateChatDto getOrCreatePrivateChat(
            @RequestParam String sender,
            @RequestParam String receiver
    ) {
        PrivateChat chat = privateChatService.getOrCreatePrivateChat(sender, receiver);
        return new PrivateChatDto(chat.getId(), chat.getUser1().getUsername(), chat.getUser2().getUsername());
    }

    @GetMapping("/private")
    public List<ChatMessageDto> getPrivateChatMessages(@RequestParam Long privateChatId) {
        List<ChatMessage> messages = chatMessageRepository.findByPrivateChatIdOrderByTimestampAsc(privateChatId);

        return messages.stream()
                .map(message -> new ChatMessageDto(
                        message.getContent(),
                        message.getTimestamp().toString(),
                        null, // groupId stays null for private chats
                        privateChatId,
                        message.getSender().getId(),
                        message.getSender().getUsername()
                ))
                .toList();
    }
}
