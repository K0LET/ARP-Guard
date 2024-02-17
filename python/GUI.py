import pygame
from button import Button
import SpoofRemove
import sys


class GUI:
    def __init__(self):
        pygame.init()
        self.width, self.height = 1400, 900
        self.display = pygame.display
        self.screen = self.display.set_mode((self.width, self.height), pygame.RESIZABLE)
        self.display.set_caption("Arp Guard")
        self.icon = pygame.image.load("assets/icon.png")
        pygame.display.set_icon(self.icon)

        self.clear_arp = Button(text_input="Clear ARP cache", pos=(400, 300))
        self.get_arp = Button(text_input="Get ARP cache", pos=(400, 400))
        self.buttons = [self.clear_arp, self.get_arp]

        self.background_image = pygame.image.load("assets/background.png")
        self.background_rect = self.background_image.get_rect()

        self.back_image = pygame.image.load("assets/back.png")
        self.back_rect = self.back_image.get_rect()

    def run(self):
        while True:
            mouse_pos = pygame.mouse.get_pos()
            self.clear_arp.change_color(mouse_pos)
            self.get_arp.change_color(mouse_pos)
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    pygame.quit()
                    sys.exit()
                elif event.type == pygame.MOUSEBUTTONDOWN:
                    if self.clear_arp.check_for_input(mouse_pos):
                        SpoofRemove.run_as_admin()
                    if self.get_arp.check_for_input(mouse_pos):
                        SpoofRemove.run_cmd("arp -a")
                elif event.type == pygame.VIDEORESIZE:
                    self.width, self.height = event.size

            # self.background_image = pygame.transform.scale(self.background_image, (self.width, self.height))
            self.background_rect = self.background_image.get_rect(center=(self.width // 2, self.height // 2))
            self.back_image = pygame.transform.scale(self.back_image, (self.width // 2, self.height))
            self.back_rect = self.back_image.get_rect(center=(self.width // 2, self.height // 2))

            # Other game logic and drawing here

            # Draw the resized background image
            self.screen.blit(self.background_image, self.background_rect)
            self.screen.blit(self.back_image, self.back_rect)
            # self.screen.fill((255, 255, 255))
            self.clear_arp.x_pos = self.width // 2
            self.clear_arp.y_pos = self.height // 2
            self.clear_arp.update(self.screen)
            self.get_arp.x_pos = self.width // 2
            self.get_arp.y_pos = self.height // 2 + 100
            self.get_arp.update(self.screen)
            self.display.flip()


def main():
    g = GUI()
    g.run()


if __name__ == '__main__':
    main()


