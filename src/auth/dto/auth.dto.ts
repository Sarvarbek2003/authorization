import { IsString, Length } from "class-validator"
import { ApiProperty } from "@nestjs/swagger";

export class AuthDto {
    @IsString()
    @Length(12,12)
    @ApiProperty({type: String, description: 'Phone number'})
    phone: string
}