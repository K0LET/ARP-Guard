import pygame


class Button:
    def __init__(self, image=None, pos=(0, 0), text_input="", font=None, font_size=50, base_color="lightblue", hovering_color="white"):
        self.image = image
        self.x_pos = pos[0]
        self.y_pos = pos[1]
        self.font = self.get_font(font, font_size)
        self.text_input = text_input
        self.base_color, self.hovering_color = base_color, hovering_color
        self.text = self.font.render(self.text_input, True, self.base_color)
        self.text_rect = self.text.get_rect(center=(self.x_pos, self.y_pos))
        if self.image is None:
            self.image = self.text
        self.rect = self.image.get_rect(center=(self.x_pos, self.y_pos))
        self.enabled = True

    @staticmethod
    def get_font(font, size):  # Returns Press-Start-2P in the desired size
        if isinstance(font, pygame.font.Font):
            return font
        return pygame.font.Font(font, size)

    def get_width(self):
        return self.text.get_width()

    def get_height(self):
        return self.text.get_height()

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def update(self, screen):
        if self.enabled:
            if self.image is not None:
                self.rect = self.image.get_rect(center=(self.x_pos, self.y_pos))
                screen.blit(self.image, self.rect)
            if self.text != "":
                self.text_rect = self.text.get_rect(center=(self.x_pos, self.y_pos))
                screen.blit(self.text, self.text_rect)

    def check_for_input(self, position):
        if self.enabled:
            if position[0] in range(self.rect.left, self.rect.right) and position[1] in range(self.rect.top, self.rect.bottom):
                return True
            return False

    def change_color(self, position):
        if self.enabled:
            if position[0] in range(self.rect.left, self.rect.right) and position[1] in range(self.rect.top, self.rect.bottom):
                self.text = self.font.render(self.text_input, True, self.hovering_color)
            else:
                self.text = self.font.render(self.text_input, True, self.base_color)
