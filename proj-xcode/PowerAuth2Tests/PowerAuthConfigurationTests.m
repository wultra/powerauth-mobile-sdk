/*
 * Copyright 2026 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import <XCTest/XCTest.h>
@import PowerAuth2;
@import PowerAuthCore;

@interface PowerAuthConfigurationTests : XCTestCase
@property (nonatomic, strong) NSString * goodSdkConfiguration;
@property (nonatomic, strong) PowerAuthCoreData * goodEEK;
@property (nonatomic, strong) PowerAuthCoreData * badEEK;
@end


@implementation PowerAuthConfigurationTests

- (void) setUp
{
    _goodSdkConfiguration =
        @"ARDV9ZPCmbBxQOuvwBEet0nnEIYRtwiuK6sEI58YecWmHcYEAUEEIOUWfl7mNjd72rmyrWcqNnPB"
        @"8rT75WuAZDopD+5wSM7ibOvJ8zVolKJ3G45VvxFsBPxut118YPpNqyuKnpnuAAJhBLxTNONEcqW+"
        @"Pgeps0YK3rGN2fDxkR/91Ovpl4H09ob1J59EP1N5RXIAxgDPjqTr9iLxAFQ/Sh+dJcmNT1CAUB12"
        @"S0BCK2W0U3/q9CKbzzJMuNGRWTa9yIfqT78udJq4CAOHtjCCB7IwCwYJYIZIAWUDBAMSA4IHoQCr"
        @"+GhdgN4woE6dXE0EAWI1/AgWrFgN5ty3p+m42q0g+VhvZLv5DvtPwEDyBxa1+gEuMdNaMNmYih36"
        @"2DpZZof5kWgLLX59hV+4SfYrJgvMf4I+221hiUmdC19S+n8MHhi148WPdTQ6XS+P+qDEp8xKRIbp"
        @"ZnL189QcHuxSWY5mHZYLJ8vOTQeTEifRT2S6n+mcqybT5mTiiSh0q/tumcHMmydEWbc82/kA4vPJ"
        @"PwQ2hYRjUCZgKIHFklxmLlVNd2AMsx+KD/Fa/QPki79uAoAN+4E395MXUBz904l/ry+OD1dw/12n"
        @"f0qOMcS0GgHzlDVfL6Nl/UEHZ8WNB70ryLyayUxLLG0vmFOhKJAZ4yJKkfKm32Ku8tUupn2QpJ7X"
        @"drU7mop8dATcEOT3T6sFDoopCAbIoAJmU98uiauwIopCUVrOU1KoWYvW8LFSH/UlGXg6BdEfEvMW"
        @"cQtBfHE/BgQLHmYVaaXqXCitL7Bz4FhDEpcVOWoxwcX/VN4/S8449Du/1LLUx5qAcS8iip8/YzUN"
        @"4CYwuJmRPj1RM3m7IQlYrDaxHZ2ZZXYdoFUTkYEakYOyX2Iut6YaPO1A4my2Z2Avl/XzD3kN/wYI"
        @"gig8gcp+QpJ1Za1+gK+J6ydMxT8h5oEv2vCTDEiwb2aHAX1kW8Kep0u+RtemZdOV6LUrBkvdGjTD"
        @"0L3T/3cLZj6nzkS9VVje4qdWvUhkwPAldpYKpN0orAjyPKlp9h/qzSj859/uVTPN2gPhEgN0l1CB"
        @"Fa781KALGIfMGY2sv2Z3WWPNtlwdiH9U7074TBNpWg1HD7ztZxr8lKbYTc38X54//UZwWjG8qAtT"
        @"1KZh/WQJ1vN0AMmpbBmXf7vQfIhiMF5HJEgtshWPmUVGtG2CR37sTUFDRljZZycfVbIY7T6PQHQ2"
        @"GE8lDUT9jUl4lGJq/1ebUfGvxY0jE1S8RAz7SxC9LTuf398NBj68AguH7kTk+YblkWhUPYHlpSNs"
        @"MRERc9vYM+8YQ5+HOUvZLBUjSuEs9UAXSndcu6nXQILPYCAoHfgmR+XBQC0TTW29v070YRuOy6Gn"
        @"AZxwLe6bbAGhoI5Pij8U3siEKCJFRSDeYdHYvDIeErnqzisnWcN8m3XWaVD/2My0jYd1Gc9v34JJ"
        @"rbMS1PnqXGh8/s+Wz3gHnt3Qj9OaHXVy0JaDA15A62/G1rN1bXuriSLylYeRzlGuAEwS9oseTX/v"
        @"rFvB8KiXFGNLJiJOl4AXkNi7tL1tkkWivffqa2NYZyazY2wbTkOpcHw7Z/gnOD5As7GQCQrySX/W"
        @"bOfT5bTzD6RoYX6DUosf9v3kG58miSOCM9NnE7otgr9znNv7uHBN3ukqx7WZYib+wmN+EsM4ZZbV"
        @"/M5YPQUlXzfLqCT7c1Tk/VVA2QJVKHwHAIBJZKaqs6i1wtyr1bVcFZpcQ4oabk3nl0vecZOYdEhW"
        @"rKwBzVfW2FVFPsx4s3mFGLxTs4TUWj+G21DimE6WQuKsztIKanoPkda+uAfwWvEL/B2e71jurp8P"
        @"yFSz2zD1rl36opHfBRkmlOY+s5TI7IgxTjvHdoY1m7DlfdmorEAiJnLmklCpPzVjMM08RZgsLcZk"
        @"ilbDxkSF4Yb0UuAYZKaZEpGRZUAPhzxV3NessgB3FO/hjXZ9Jh2IwZecgfZRVLVvjgfXgGwjCMBI"
        @"mRvSublX4p3qtD7iaHBqDEQL41IAhAC1v3LbS5AM7f12kiwS3byrcCQ0zDFTK4nTbSsWHQW5imMC"
        @"0TqlsDGWLiupRZWBtpPXMqY9Z7NNqHkHVIh3D6b0S1vFdCU1ApEm9K9XWxtBi2x+tyWQ6HKDW2R8"
        @"MbuY8/2Izver6rlnFsncLIUL8FVLZHJ2QlWAEM+gpeYzIKXm0eGyq0ZlzPoiAt6ivyTcENVbuQg5"
        @"dZHRP7q6NH/DH+t64pycJjJNLB7xH44LnVc8SyC36wmeow7g4m7p2RSbJVN+xVeD1mlviQyRvLPa"
        @"XKsm5xIIWX5t6zDprXMBLkj2UkiuoM6Hmed0vkS2erzGwKa6OcxhfHwoCBQgGiMSOJ2G/OVNgMmL"
        @"HmoH2MR7SqlczO0hlKd3q4DYTZ+fogkOeo6PrG9Wr0mC9uX0QXpVGFq/3rhGTpqH4iPcfk0taTtK"
        @"oabLyEb5MbzwY7Z2uw9Eqe2hPcJqpmVjkg5nCm4itufLp4uPDLqNx7yYb31M4vlCyLjLkjDcBLTu"
        @"CAlaDiZlDPJpp308GcargrdBWRft5w5KUmrpcFu1uqLQZpuPPgNW1xzoCDjRQOk5jsnnH2sb6/z4"
        @"68cPvlRCgPZQzQ2zvRPku31bTirR1iVI6zLlKZxyFEd7jgP+DwfvezWGx2VM3yrFhZSZlOXiEPgV"
        @"5uAOvhpuCfnHrw1BKMyaikaRin7btLfU84Wvz909btyTs6hJzhT2plYYpp5wwXrl3KKhJDMAET+f"
        @"qoFkbMm5o9KVPgYm4TXjSyx1CjgUtShxqyz8TEuYII0OFtFprstzE1dvuzi//fHM4tqQlb1RMVca"
        @"tVMMcg+gxS6ZiSO0V/uZTchFQeCBe0rkIphL0MdbMS1A4st2YehkIz4OA4fXCKDadKmrGS/WszTL"
        @"gNw2gg3ql3DlaKj/rwSKNjCCCjIwCwYJYIZIAWUDBAMTA4IKIQCc8aFWGLZ7eVG2adMiexGqyrPu"
        @"eRRZ7nsq1R29Q2cIMYPWyaTEguOMU5wiGC97cXeerl/sC3gLDWAIznEVdhfFw8FmsNwDBtz7d4jO"
        @"mFLEBt79QmJECPkvDcGKi5vicSjpGq4I55pGN0RjZNkuIM8lyGRlxft0FlS71xQwphY/37SXPuzA"
        @"7P2gNfhzPT53OTJTRhxlKq61Sp26981+fHfAkMvL+2vegKSnhW14GnOeIQ5oabMNrF9niYrJWcT3"
        @"CY+5TLWajHH0oqTtHh/UY3M6xl9lOlXmemOX+PXh1ce3xdPHJgGp6eBW+1tXal8TJYbXBdYfBY18"
        @"rUVRVLj2Hb0YrUmuSjtZ5a5lzh0iiqjhKWEOMdMU44ZaqqBm+/KT4SYCZ/w3dgVwzmDNIR5QN8S8"
        @"VRX13dZL45RMewL/mk2aZg7BdEYoy5hsRycP8dF491NQg5JxOt7338FRwDzzvCximmOh5Su1RHvm"
        @"/CEgrZ3+2ee/5Wgpj+d4nVnwMvzr0lrlQA/XPh0FBJJ/XOfXw08HoT0xM0aADqCIP7XwVfuw6DQd"
        @"n6L0XltZGE0pWDVfN98LDP/EEJLEvaPx1zJGhnFGYdaqDByolYhh2u52HrBZUpY+yBu1fAOLTkR6"
        @"r7Rt01hAOGM7ciPfaFKRTtAMRbjOTJ0Jhmlk+Wh4DQWGTWJL4hOvSC8c4Qc7l657/6MS/Mcm3GND"
        @"1tcW4F7ebWo9ybbQCsyg3vITlf5tI8OcHir3QMbcUYiqzI5vO0MnvF4aKH1Uk0raOuHgknBKCUUB"
        @"liH/BuT2zdq+/46m1uxXcwe2rLPWAABXAqRmCpXwOX7aw1mNFHXSuSm7e3OPw/85rspns5Ppb5mI"
        @"1kB1JOuh34bxzZeNHqbPYH5ng8xhTp6i/oSe8a3a28jqDX/7cvy332bllxmm3p4SZDQlmCX2A06e"
        @"VjcNNwxQUbApqsiQgCRMO6CiJPRap2zcpxNwYtUpwDFqtxBnbXWXLxVnCtllpgxEEC6RLia13ds3"
        @"R/o5+dQz0g3ZlSQSjyda0NxMshWScdrnKz64WFpXEM1StuhhHFmXTxc7Cp3EjaHnheHJLAzVWMXu"
        @"YHaM23e41SNobVaDTxn2ngyc0q9isg0h2YZybq7vIOzXbkUOQM0Zha3BinZVhMG4F6ddaCNuEAoE"
        @"QUOSGHwFFB1sZh+0gBze/2Z9KNIh+kvvt5u376DzCZALVpLxDGVDa09ZWDC5YChTHmV3k5NkbJ9B"
        @"oM47KGqh8P4D24axTN6rAKN0eoQHsYf7/OPwgtehneefGX3JoWGsBDmOM0ti0kUpVwQVc/8GyRQl"
        @"6RFt8wwgNSbFSi+kWdKg+ee7JmP1biUselWk0nKbZ+I49L9ZSuPYDL3HdeniKBzTMmG5SxaXa7sD"
        @"LOmvTW82iuwFDp5mic7SxlaoqvIChGdvYGEpa6oGrArSM1yu7kbRbVyRgouTMIMfjPBwP+hhoC39"
        @"w073xKGMNzpqFxZtcNjj5cWcBop7h/n+uXLHatFpTS8nnrxnNd5Bc1UdMKtzpL2+AHs6AYbnZd75"
        @"O9Tmib40CII8/S0oASTFiLBEo4k5vaKk/84wU/kYWQoLYMsJ3Q3+NIzygW3GefzTbCla//pd8gDG"
        @"eX9peMs6woFxaV9OPq0gmu/MAveD6Mjz+VyPU69lMgdq6Bsste6M6xUeMKNvE5Wm7ZiReS3AYisU"
        @"NeNa3k7q5nfe5lvkKoFkHPhjDw25eGFY7n/KQ0uoM6hOaeWSv2Lq2oEUhw/dYIokbVoeHW0zWc5J"
        @"/WYVbCfUL0U6ci/D6Wz6GfiPpe7j+JrwVFUVDF4P6ZZzTqo6Oum7lZpC5LCmLdWWTacGGaBp0H9S"
        @"kcxi+Nppv5PtSe4KJOpni0VdFILjvZQT332Zn8K36KYjyeOjiq8SyxC/fpTM+bWBSq/4iuIdLxHo"
        @"J00fnGawIvQKYrRZCx+BJ93xlKnMsEslfjb6kwmI/gd1Rbcxl/5uTTYrwDD3T4YDjKi52gMpejph"
        @"fbXll/+zBPrGbLoyZpJetVtDEOumiaLNRtD5vIeOLbaYF65IO46wcbo7Kg3kGojdNJbl+4bZKBnU"
        @"0NmdOOW/GwmbhvKyoLw0Gu+XaT39xWGyPV25CmUOpi/oSGiCSbSt3QTnrkeeFC6ELEE5p/UklUEd"
        @"nRacb089piy08jn1KS5phs9TEmzdygt7YIepde/4UJDgC45judJ0Jn5nsowttk9rho3KP3nyUrep"
        @"MZ4nTgkaf5CREpde6G8zZE5VKL2/DWWlSvAnk0gAR/6+BqqD9VEFSjhCNSMr0Y46SulTGALselZ0"
        @"CCMx6VbUd2NMkIW7wnmzsV9zon96GcfrzDDcrK76LhzKMC/rzj+Cf1/Gms/rek1uk+H0QsnRGPWK"
        @"oT7N9TNJPoSjKBlRCWhyu5jIQ1oT91l0bilGmAFocnamISRFouS+K1cbSJY0t+mb+raT4SeyG5gA"
        @"nTpquEXeslVKwfaCPd/B4LBqFwD209ckP7Fg9BO40Hlu9QBPg/GLn5yhpD7gO+mpu6hJIDMKIkIB"
        @"6E+dUB9DOh1G5EC7k3Eqba2znMjgCeRGHjjozvj/s1xttDPrT/wLZGqqhOVkyhzAsEh0lrbijvKg"
        @"yu+4x3PShsoceLD66vC8uAPcMVU7tWuUXHVa1JiMwkltXePACSIwGxRlIbvF+j5wv7CNel0c18PI"
        @"4NgPFVXfQFF4be/xAr8mb3jZz3yKewJvc5oW9D98GoYMh5UH4RN9OIaXd9GHSZ3vKKuUf6RcvP8Q"
        @"tlBWlH73/OiQ1H7pFWyd7t+pEb+RzFUUoLVrW0oEB45g3UNNqb/zysgaHBbglVs8qbvTJ9Wlm2mx"
        @"nINWrJsBLPTPUjXNBKMTMm1Brf4UOrKtHAQqySMJ3GlpM2hjq2FkThHNEbZPfFCIU3K0ucbcMSH5"
        @"8YtLk2PSkytguOoKoHDXmJ+GS5Iy0JHoJt3tjfvHGsfzXu3zd7V5OozD/yqRfHioYXPW+QkU9dFy"
        @"UNQAp1UaSNXXLRFGCak9vuTKMa3CT+uLp2SDoWWZv9W//DaPCiM/nIpQcCy8yeepqcQrSeVGSwLM"
        @"ZcSUm13OXBaYlVcHWTosq08sizIX7uEeyJrT0rSVHZLx14YEh/WbQnx2TKTSVArgJ+RzCCL1+cqL"
        @"aSVdHURZ0fyC5XA5AHcXQz5wtbO8Kgb3IC0d9O1SdTL2F5mzbYz86i3hXDNP/OQ4DmKCRti9RsjL"
        @"xuILKkGQrvMqXTdnPVVFwJQ+3T4YZ2tPnisVKePJpCxpeZWLo+VaTQSvxbMYml97kfP4Bd3+8ngH"
        @"q+jg3A2xFmu0Kv2CJY8eKi+Hjg5DYbqWQNUXHbv7uUuVHCgJmT6azse4x357y4qEdzXDrslMvPyg"
        @"jcmIgTBMNVsGjO7JhZR4g5WmUvQ7/BveNv0KXX7MLoeWqbGVq+m3Ap14pZ387ajzR+35W8aDRWgY"
        @"gKU17hnlpfo=";
    _goodEEK = [PowerAuthCoreSession generateFactorKekForProtocolVersion:PowerAuthCoreProtocolVersion_V3 error:nil];
    _badEEK = [PowerAuthCoreSession generateFactorKekForProtocolVersion:PowerAuthCoreProtocolVersion_V4 error:nil];
}

- (void) testDiscontinuedEEK
{
    PowerAuthConfiguration * config = [[PowerAuthConfiguration alloc] initWithInstanceId:@"default"
                                                                         baseEndpointUrl:@"https://test.server.org/powerauth"
                                                                           configuration:self.goodSdkConfiguration];
    XCTAssertTrue([config validateConfiguration]);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    config.externalEncryptionKey = _goodEEK;
    XCTAssertTrue([config validateConfiguration]);
    config.externalEncryptionKey = _badEEK;
    XCTAssertTrue([config validateConfiguration]);
#pragma clang diagnostic pop
}

@end
