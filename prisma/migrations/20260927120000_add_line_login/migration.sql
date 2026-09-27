-- AlterTable
ALTER TABLE `User` ADD COLUMN `line_id` VARCHAR(191) NULL,
    MODIFY `auth_provider` ENUM('EMAIL', 'GOOGLE', 'FACEBOOK', 'LINE') NULL;

-- CreateIndex
CREATE UNIQUE INDEX `User_line_id_key` ON `User`(`line_id`);

